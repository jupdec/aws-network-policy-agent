// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
//     http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

package rpc

import (
	"context"
	"net"
	"os"

	"github.com/aws/aws-network-policy-agent/controllers"
	"github.com/aws/aws-network-policy-agent/pkg/logger"
	"github.com/aws/aws-network-policy-agent/pkg/utils"

	"github.com/aws/amazon-vpc-cni-k8s/rpc"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
	"k8s.io/apimachinery/pkg/types"
)

func log() logger.Logger {
	return logger.Get()
}

const (
	grpcHealthServiceName = "grpc.health.v1.np-agent"
)

// server controls RPC service responses.
type server struct {
	policyReconciler        *controllers.PolicyEndpointsReconciler
	clusterPolicyReconciler *controllers.ClusterPolicyEndpointsReconciler
	rpc.UnimplementedNPBackendServer
}

// EnforceNpToPod processes CNI Enforce NP network request
func (s *server) EnforceNpToPod(ctx context.Context, in *rpc.EnforceNpRequest) (*rpc.EnforceNpReply, error) {
	// If NPA is disabled, controllers are nil. The gRPC server still runs to serve CNI requests,
	// so return success without enforcing any policy.
	var err error
	peReconcilerReady := s.policyReconciler != nil && s.policyReconciler.GeteBPFClient() != nil
	cpeReconcilerReady := s.clusterPolicyReconciler != nil && s.clusterPolicyReconciler.GeteBPFClient() != nil

	if !peReconcilerReady && !cpeReconcilerReady {
		log().Debug("Network policy is disabled, returning success")
		response := rpc.EnforceNpReply{
			Success: true,
		}
		return &response, nil
	}

	if peReconcilerReady != cpeReconcilerReady {
		err = errors.New("One of the policy reconcilers is not ready")
		log().Errorf("One of the policy reconcilers is not ready, policyReconcilerReady: %t, clusterPolicyReconcilerReady: %t", peReconcilerReady, cpeReconcilerReady)
		response := rpc.EnforceNpReply{
			Success: false,
		}
		return &response, err
	}

	log().Infof("Received Enforce Network Policy Request for Pod: %s Namespace: %s Mode: %s", in.K8S_POD_NAME, in.K8S_POD_NAMESPACE, in.NETWORK_POLICY_MODE)

	if !utils.IsValidNetworkPolicyEnforcingMode(in.NETWORK_POLICY_MODE) {
		err = errors.New("Invalid Network Policy Mode")
		log().Errorf("Network Policy Mode validation failed: %s, error: %v", in.NETWORK_POLICY_MODE, err)
		return nil, err
	}

	// The pod is enforced under the identity its labels give, read from the API server; the
	// name in the request is only used to find the pod. See controllers.PodEnforcer.
	pod := types.NamespacedName{Name: in.K8S_POD_NAME, Namespace: in.K8S_POD_NAMESPACE}
	if err = s.enforcer().EnforceNewPod(ctx, pod, int(in.InterfaceCount), in.NETWORK_POLICY_MODE); err != nil {
		return nil, err
	}

	resp := rpc.EnforceNpReply{
		Success: true,
	}
	return &resp, nil
}

func (s *server) enforcer() controllers.PodEnforcer {
	return controllers.PodEnforcer{Policy: s.policyReconciler, ClusterPolicy: s.clusterPolicyReconciler}
}

// DeletePodNp processes CNI Delete Pod NP network request
func (s *server) DeletePodNp(ctx context.Context, in *rpc.DeleteNpRequest) (*rpc.DeleteNpReply, error) {
	// We don't need CPE reconciler check here, since we only need one client during the deletion flow to delete the relevant BPF probes and map entries from bpfclient
	if s.policyReconciler == nil || s.policyReconciler.GeteBPFClient() == nil {
		log().Debug("Network policy is disabled, returning success")
		success := rpc.DeleteNpReply{
			Success: true,
		}
		return &success, nil
	}

	log().Infof("Received Delete Network Policy Request for Pod: %s Namespace: %s", in.K8S_POD_NAME, in.K8S_POD_NAMESPACE)
	pod := types.NamespacedName{Name: in.K8S_POD_NAME, Namespace: in.K8S_POD_NAMESPACE}

	// The pod is released from the identity it is attached to; its labels may be gone.
	err := s.enforcer().DeletePod(ctx, pod)
	if err != nil {
		log().Errorf("Failed to delete BPF probes for pod: %s namespace: %s, error: %v", in.K8S_POD_NAME, in.K8S_POD_NAMESPACE, err)
		return &rpc.DeleteNpReply{Success: false}, err
	}

	resp := rpc.DeleteNpReply{
		Success: true,
	}
	return &resp, nil
}

// RunRPCHandler handles request from gRPC
func RunRPCHandler(policyReconciler *controllers.PolicyEndpointsReconciler, clusterPolicyReconciler *controllers.ClusterPolicyEndpointsReconciler, npaSocketPath string) (<-chan error, error) {
	log().Infof("Serving RPC Handler on Unix socket: %s", npaSocketPath)

	if _, err := os.Stat(npaSocketPath); err == nil {
		log().Infof("Removing stale socket file: %s", npaSocketPath)
		err = os.Remove(npaSocketPath)
		if err != nil {
			log().Warnf("got error in removing socket file %v", err)
		}
	}

	listener, err := net.Listen("unix", npaSocketPath)
	if err != nil {
		log().Errorf("Failed to listen on unix socket: %v", err)
		return nil, errors.Wrap(err, "network policy agent: failed to listen on unix socket")
	}
	grpcServer := grpc.NewServer()
	rpc.RegisterNPBackendServer(grpcServer, &server{policyReconciler: policyReconciler, clusterPolicyReconciler: clusterPolicyReconciler})
	healthServer := health.NewServer()
	// No need to ever change this to HealthCheckResponse_NOT_SERVING since it's a local service only
	healthServer.SetServingStatus(grpcHealthServiceName, healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(grpcServer, healthServer)

	// Register reflection service on gRPC server.
	reflection.Register(grpcServer)
	errCh := make(chan error, 1)
	go func() {
		if err := grpcServer.Serve(listener); err != nil {
			errCh <- errors.Wrap(err, "network policy agent: grpc serve failed")
		}
		close(errCh)
	}()
	log().Info("Done with RPC Handler initialization")
	return errCh, nil
}
