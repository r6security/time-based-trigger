/*
 * Copyright (C) 2023 R6 Security, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the Server Side Public License, version 1,
 * as published by MongoDB, Inc.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * Server Side Public License for more details.
 *
 * You should have received a copy of the Server Side Public License
 * along with this program. If not, see
 * <http://www.mongodb.com/licensing/server-side-public-license>.
 */

package controller

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/go-logr/logr"
	amtdapi "github.com/r6security/phoenix/api/v1beta1"
	"github.com/robfig/cron"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/strings/slices"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// PodReconciler reconciles a Pod object
type PodReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Clock
}
type previousRunCalculator func(*corev1.Pod) (*time.Time, error)

const TimeBasedTriggerDomain = "time-based-trigger.amtd.r6security.com"
const TimeBasedTriggerEnabledAnnotation = TimeBasedTriggerDomain + "/enabled"
const TimeBasedTriggerScheduleAnnotation = TimeBasedTriggerDomain + "/schedule"

var ErrorMissingScheduleAnnotation = errors.New(fmt.Sprintf("Missing annotation for scheduling. Add %s as an annotation", TimeBasedTriggerScheduleAnnotation))

// Neat trict to make testing easier
type realClock struct{}

func (_ realClock) Now() time.Time { return time.Now() }

// clock knows how to get the current time.
// It can be used to fake out timing for testing.
type Clock interface {
	Now() time.Time
}

type SchedulableDuration struct {
	duration time.Duration
}

func (de SchedulableDuration) Next(t time.Time) time.Time { return t.Add(de.duration) }

var previousRun previousRunCalculator

//+kubebuilder:rbac:groups=apps.amtd.r6security.com,resources=pods,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=apps.amtd.r6security.com,resources=pods/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=apps.amtd.r6security.com,resources=pods/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the Pod object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.15.0/pkg/reconcile
func (r *PodReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.Log.WithName("PodReconciler").WithValues("namespace", req.Namespace, "name", req.Name)

	pod := &corev1.Pod{}

	if err := r.Get(context.Background(), req.NamespacedName, pod); err != nil {
		log.V(2).Info("Unable to fetch Pod", "reason", err)
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	enabled, ok := pod.Annotations[TimeBasedTriggerEnabledAnnotation]
	if !ok {
		log.V(2).Info("time-based-trigger annotation is missing. Ignore this pod")
		return ctrl.Result{}, nil
	}
	log.Info("Found pod with Time Based Trigger annotation")

	if e, err := strconv.ParseBool(enabled); err != nil || !e {
		log.Info("time-based-trigger disabled or malformed. Skipping this pod")
		return ctrl.Result{}, err
	}

	if pod.DeletionTimestamp != nil {
		log.V(2).Info("Ignore terminating pod", "deletionTimestamp", pod.DeletionTimestamp)
		return ctrl.Result{}, nil
	}

	log.V(2).Info("Observed pod", "phase", pod.Status.Phase)

	schedule, ok := pod.Annotations[TimeBasedTriggerScheduleAnnotation]
	if !ok {
		log.Info("Schedule annotation is missing for this pod")
		return ctrl.Result{}, ErrorMissingScheduleAnnotation
	}
	log.Info("Found schedule annotation for this pod", "schedule", schedule)

	// TODO: make it possible through a configuration that the lifetime can be calculated to different pod phases
	// e.g. relative when it become ready (https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/#pod-conditions)
	// or when the pod reached its Running state (https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/#pod-phase)

	sched, err := cron.ParseStandard(schedule)
	if err != nil {
		log.Info("Cannot parse schedule as a valid cron pattern", "pattern", schedule)
		log.Info("Fallback to simple duration parsing")
		d, err := time.ParseDuration(schedule)
		if err != nil {
			log.Error(err, "Cannot parse schedule as a standard duration or as a cron pattern!")
			return ctrl.Result{}, err
		}
		sched = SchedulableDuration{d}
	}

	// TODO: we cannot use pod annotation in real scanerios
	// because it requires a role which can patch any pod :( That won't be a secure approach
	// Instead we can restore the last run time from the last SecurityEven we created. That is
	// more secure and more realistic approach. In case we will define a custom resource for this
	// operator (e.g. to create a label based restart rule) we can store the last run in its state.

	lastRun, err := lastSecurityEventTimestamp(ctx, pod, r.Client, log)
	if err != nil {
		lastRun = pod.CreationTimestamp.Time
		log.Info("Fallback to pod creation timestamp", "fallback", lastRun)
	}

	nextRun := sched.Next(lastRun)
	log.Info("Was able to calculate next run regarding latest one", "last", lastRun, "next", nextRun)

	// multiple call at the same time may cause issue because the secevent was not created yet (only pending in k8s api)

	if nextRun.Equal(r.Now()) || nextRun.Before(r.Now()) {
		log.Info("Time passed, lets create an event")
		secEvent, err := buildNewSecurityEvent(pod, strconv.FormatInt(nextRun.Unix(), 10))

		if err != nil {
			log.Error(err, "Cannot build the security event")
		} else {
			err := r.Create(ctx, secEvent)
			if client.IgnoreAlreadyExists(err) != nil {
				log.Error(err, "Cannot create the security event")
			} else if apierrors.IsAlreadyExists(err) {
				log.Info("Already exists error", "e", err)
			} else {
				log.Info("SecurityEvent was created", "SecurityEventName", secEvent.Name)
			}
		}
		// We do not care if we missed 1 or 1000 schedule, we generate one event and next one will be in the future
		nextRun = sched.Next(r.Now())
	} else {
		log.Info("Still have time until the next schedule, don't need to generate any event")
	}
	nextReconcile := nextRun.Sub(r.Now())
	log.Info("Schedule next reconcile", "at", nextReconcile)
	scheduledResult := ctrl.Result{RequeueAfter: nextReconcile}

	return scheduledResult, nil
}

func buildNewSecurityEvent(pod *corev1.Pod, nameID string) (*amtdapi.SecurityEvent, error) {
	name := fmt.Sprintf("tb-%s-%s", pod.Name, nameID)
	secEvent := &amtdapi.SecurityEvent{
		ObjectMeta: metav1.ObjectMeta{
			Labels:      make(map[string]string),
			Annotations: make(map[string]string),
			Name:        name,
			Namespace:   pod.Namespace,
		},
		Spec: amtdapi.SecurityEventSpec{
			Targets:     []string{fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)},
			Description: "Generated by a time based even",
			Rule: amtdapi.Rule{
				Type:        "timed",
				ThreatLevel: "info",
				Source:      "TimeBasedTrigger",
			},
		},
	}

	return secEvent, nil
}

func lastSecurityEventTimestamp(ctx context.Context, pod *corev1.Pod, client client.Client, log logr.Logger) (time.Time, error) {
	var secEvents amtdapi.SecurityEventList
	lastRun := pod.CreationTimestamp.Time

	if err := client.List(ctx, &secEvents); err != nil {
		log.Info("Cannot get the SecurityEvent list.")
		return lastRun, err
	}

	if len(secEvents.Items) == 0 {
		log.Info("Cannot find any SecurityEven.")
		return lastRun, errors.New("Cannot find any SecurityEvent")
	}

	lastEvent := lastRelevantSecurityEvent(secEvents.Items, pod)
	log.V(2).Info("Found secevent", "lastEvent", lastEvent)

	if lastEvent == nil {
		log.Info("There is no previous SecurityEvent for this pod.")
		return lastRun, errors.New("No security event for given pod")
	}
	log.Info("Found sec event for this pod", "SecurityEventName", lastEvent.Name, "SecurityEventTimestamp", lastEvent.CreationTimestamp.Time, "lastEventTargets", lastEvent.Spec.Targets)
	lastRun = lastEvent.CreationTimestamp.Time
	return lastRun, nil
}

func lastRelevantSecurityEvent(securityEvents []amtdapi.SecurityEvent, pod *corev1.Pod) *amtdapi.SecurityEvent {
	var lastEvent *amtdapi.SecurityEvent
	for _, securityEvent := range securityEvents {
		secEvent := securityEvent
		if slices.Contains(secEvent.Spec.Targets, fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)) && secEvent.Spec.Rule.Source == "TimeBasedTrigger" {
			if lastEvent == nil || secEvent.CreationTimestamp.Time.After(lastEvent.CreationTimestamp.Time) {
				// cannot point to the memory address of the range variable :(
				lastEvent = &secEvent
			}
		}
	}
	return lastEvent
}

// SetupWithManager sets up the controller with the Manager.
func (r *PodReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.Clock == nil {
		r.Clock = realClock{}
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Pod{}).
		Complete(r)
}
