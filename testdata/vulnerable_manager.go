package main

// vulnerable_manager.go — Contains ALL 10 anti-patterns for scanner evaluation.

import (
	"context"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

// AP-4 + AP-10: No namespace scoping and no managed-fields stripping
func setupManager() (ctrl.Manager, error) {
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Cache: cache.Options{
			ByObject: map[client.Object]cache.ByObject{
				// AP-6: Unfiltered ByObject entries
				&corev1.ConfigMap{}: {},
				&corev1.Secret{}:    {},
				// This one is filtered correctly
				&appsv1.Deployment{}: {
					Label: labels.SelectorFromSet(labels.Set{
						"app.kubernetes.io/managed-by": "test-operator",
					}),
				},
			},
		},
		Client: client.Options{
			Cache: &client.CacheOptions{
				// AP-2: DisableFor configured but Owns() below creates informers anyway
				DisableFor: []client.Object{
					&corev1.Pod{},
				},
			},
		},
	})
	return mgr, err
}

type MyReconciler struct {
	client.Client
}

func (r *MyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&appsv1.Deployment{}).
		// AP-2: Owns creates informer even though Pod is in DisableFor
		Owns(&corev1.Pod{}).
		// AP-1: Predicate filter gives false safety — informer still caches everything
		Watches(&corev1.ConfigMap{},
			handler.EnqueueRequestsFromMapFunc(mapToOwner),
			builder.WithPredicates(predicate.NewPredicateFuncs(func(obj client.Object) bool {
				return obj.GetName() == "my-operator-config"
			})),
		).
		Complete(r)
}

func (r *MyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	// AP-3: Invisible informer — ServiceAccount is not in ByObject or DisableFor
	var sa corev1.ServiceAccount
	if err := r.Client.Get(ctx, client.ObjectKey{
		Namespace: req.Namespace,
		Name:      "my-sa",
	}, &sa); err != nil {
		return ctrl.Result{}, err
	}

	// AP-5: Typed/unstructured cache trap — watches typed but reads unstructured
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(schema.GroupVersionKind{Version: "v1", Kind: "ConfigMap"})
	r.Client.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: "config"}, u)

	// AP-7: Created resource missing cache label
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-monitoring-config",
			Namespace: req.Namespace,
		},
		Data: map[string]string{"key": "value"},
	}
	if err := r.Client.Create(ctx, cm); err != nil {
		return ctrl.Result{}, err
	}

	// AP-9: Update without propagating labels
	cm.Data["key"] = "updated-value"
	if err := r.Client.Update(ctx, cm); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func mapToOwner(ctx context.Context, obj client.Object) []ctrl.Request {
	return nil
}
