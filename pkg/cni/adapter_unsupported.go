//go:build !linux
// +build !linux

package cni

import (
	"fmt"

	clientset "k8s.io/client-go/kubernetes"

	"github.com/kubeedge/edgemesh/pkg/apis/config/defaults"
	"github.com/kubeedge/edgemesh/pkg/apis/config/v1alpha1"
)

// Adapter interface for non-Linux platforms (stub implementation)
type Adapter interface {
	TunToTunnel()
	WatchRoute() error
	CloseRoute()
}

var _ Adapter = (*MeshAdapter)(nil)

// MeshAdapter stub for non-Linux platforms
type MeshAdapter struct {
	kubeClient clientset.Interface
	HostCIDR   string
	Cloud      []string
	Edge       []string
	Close      chan struct{}
	setName    string
	mode       defaults.RunningMode
}

// NewMeshAdapter stub for non-Linux platforms
func NewMeshAdapter(cfg *v1alpha1.EdgeCNIConfig, cli clientset.Interface) (*MeshAdapter, error) {
	return nil, fmt.Errorf("CNI adapter is only supported on Linux")
}

// TunToTunnel stub
func (mesh *MeshAdapter) TunToTunnel() {}

// WatchRoute stub
func (mesh *MeshAdapter) WatchRoute() error {
	return fmt.Errorf("CNI adapter is only supported on Linux")
}

// CloseRoute stub
func (mesh *MeshAdapter) CloseRoute() {}

// Run stub
func (mesh *MeshAdapter) Run() {}

// CheckTunCIDR stub
func (mesh *MeshAdapter) CheckTunCIDR(outerCidr string) (bool, error) {
	return false, fmt.Errorf("CNI adapter is only supported on Linux")
}

// GetNodeNameByPodIP stub
func (mesh *MeshAdapter) GetNodeNameByPodIP(podIP string) (string, error) {
	return "", fmt.Errorf("CNI adapter is only supported on Linux")
}

// HandleReceiveFromTun stub
func (mesh *MeshAdapter) HandleReceiveFromTun() {}

// configureNodeDstRoutes stub
func (mesh *MeshAdapter) configureNodeDstRoutes() error {
	return fmt.Errorf("CNI adapter is only supported on Linux")
}

// cleanupNodeDstRoutes stub
func (mesh *MeshAdapter) cleanupNodeDstRoutes() error {
	return fmt.Errorf("CNI adapter is only supported on Linux")
}

// runNodes stub
func (mesh *MeshAdapter) runNodes(listerSynced func() bool, stopCh <-chan struct{}) {}

// OnNodesSynced stub
func (mesh *MeshAdapter) OnNodesSynced() {}

// syncNodes stub
func (mesh *MeshAdapter) syncNodes() {}

// handleAddNodes stub
func (mesh *MeshAdapter) handleAddNodes(obj interface{}) {}

// handleUpdateNodes stub
func (mesh *MeshAdapter) handleUpdateNodes(oldObj interface{}, newObj interface{}) {}

// handleDeleteNodes stub
func (mesh *MeshAdapter) handleDeleteNodes(obj interface{}) {}
