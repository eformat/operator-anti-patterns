package main

// safe_manager.go — Demonstrates correct patterns. Scanner should find zero anti-patterns here.

import (
	"context"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
)

const labelKey = "app.kubernetes.io/managed-by"
const labelVal = "safe-operator"

func setupSafeManager() (ctrl.Manager, error) {
	mySelector := labels.SelectorFromSet(labels.Set{labelKey: labelVal})

	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Cache: cache.Options{
			// AP-4 fix: DefaultNamespaces set
			DefaultNamespaces: map[string]cache.Config{
				"my-operator-ns": {},
			},
			ByObject: map[client.Object]cache.ByObject{
				// AP-6 fix: All entries have label selectors
				&appsv1.Deployment{}: {Label: mySelector},
				&corev1.ConfigMap{}:  {Label: mySelector},
			},
			// AP-10 fix: Strip managedFields from cached objects
			DefaultTransform: cache.TransformStripManagedFields(),
		},
		Client: client.Options{
			Cache: &client.CacheOptions{
				// AP-3 fix: Read-only types bypass cache entirely
				DisableFor: []client.Object{
					&corev1.Secret{},
					&corev1.ServiceAccount{},
				},
			},
		},
	})
	return mgr, err
}

type SafeReconciler struct {
	client.Client
	apiReader client.Reader
}

func (r *SafeReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.apiReader = mgr.GetAPIReader()

	return ctrl.NewControllerManagedBy(mgr).
		For(&appsv1.Deployment{}).
		// AP-5 fix: WatchesMetadata for triggers only
		WatchesMetadata(&corev1.ConfigMap{},
			handler.EnqueueRequestsFromMapFunc(safeMapToOwner),
		).
		Complete(r)
}

func (r *SafeReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	// AP-1 fix: Direct API call instead of Watches() for occasional reads
	var caCM corev1.ConfigMap
	if err := r.apiReader.Get(ctx, client.ObjectKey{
		Namespace: "openshift-config-managed",
		Name:      "default-ingress-cert",
	}, &caCM); err != nil {
		return ctrl.Result{}, err
	}

	// AP-7 fix: Resource created with required cache label
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-monitoring-config",
			Namespace: req.Namespace,
			Labels: map[string]string{
				labelKey: labelVal,
			},
		},
		Data: map[string]string{"key": "value"},
	}

	if err := r.Client.Create(ctx, cm); err != nil {
		// AP-8 fix: Handle AlreadyExists for upgrade path
		if errors.IsAlreadyExists(err) {
			base := cm.DeepCopy()
			base.Labels = nil
			base.Data = nil
			return ctrl.Result{}, r.Client.Patch(ctx, cm, client.MergeFrom(base))
		}
		return ctrl.Result{}, err
	}

	// AP-9 fix: Labels propagated during update
	cm.Data["key"] = "updated-value"
	if cm.Labels == nil {
		cm.Labels = map[string]string{}
	}
	cm.Labels[labelKey] = labelVal
	if err := r.Client.Update(ctx, cm); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func safeMapToOwner(ctx context.Context, obj client.Object) []ctrl.Request {
	return nil
}
