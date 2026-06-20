package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
)

type K8sClient struct {
	client    *kubernetes.Clientset
	config    *rest.Config
	namespace string
	secret    string
}

func NewK8sClient(namespace, secret string) (*K8sClient, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("in-cluster config: %w", err)
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("k8s client: %w", err)
	}
	return &K8sClient{client: client, config: cfg, namespace: namespace, secret: secret}, nil
}

// GetConfig reads wg0.conf from the secret and merges per-peer private keys.
func (k *K8sClient) GetConfig(ctx context.Context) (*WGConfig, error) {
	sec, err := k.client.CoreV1().Secrets(k.namespace).Get(ctx, k.secret, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("get secret: %w", err)
	}

	cfg := ParseWGConfig(string(sec.Data["wg0.conf"]))

	// Index peer private keys by public key using PEER{N}_PUBLIC_KEY / PEER{N}_PRIVATE_KEY entries.
	privKeys := make(map[string]string)
	for n := 1; ; n++ {
		pubKey := strings.TrimSpace(string(sec.Data[fmt.Sprintf("PEER%d_PUBLIC_KEY", n)]))
		if pubKey == "" {
			break
		}
		privKeys[pubKey] = strings.TrimSpace(string(sec.Data[fmt.Sprintf("PEER%d_PRIVATE_KEY", n)]))
	}
	for i := range cfg.Peers {
		cfg.Peers[i].PrivateKey = privKeys[cfg.Peers[i].PublicKey]
	}

	return &cfg, nil
}

// SaveConfig writes the updated wg0.conf and all PEER{N}_* entries back to the secret.
func (k *K8sClient) SaveConfig(ctx context.Context, cfg *WGConfig) error {
	sec, err := k.client.CoreV1().Secrets(k.namespace).Get(ctx, k.secret, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("get secret: %w", err)
	}

	if sec.Data == nil {
		sec.Data = make(map[string][]byte)
	}

	// Drop all existing PEER* keys before rewriting.
	for key := range sec.Data {
		if strings.HasPrefix(key, "PEER") {
			delete(sec.Data, key)
		}
	}

	sec.Data["wg0.conf"] = []byte(cfg.Marshal())
	for i, p := range cfg.Peers {
		n := i + 1
		sec.Data[fmt.Sprintf("PEER%d_NAME", n)] = []byte(p.Name)
		sec.Data[fmt.Sprintf("PEER%d_PUBLIC_KEY", n)] = []byte(p.PublicKey)
		sec.Data[fmt.Sprintf("PEER%d_PRIVATE_KEY", n)] = []byte(p.PrivateKey)
		sec.Data[fmt.Sprintf("PEER%d_PSK", n)] = []byte(p.PSK)
	}

	if _, err = k.client.CoreV1().Secrets(k.namespace).Update(ctx, sec, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("update secret: %w", err)
	}
	return nil
}

// WGAddPeer hot-adds a peer into the running WireGuard instance without a restart.
// The PSK is passed via stdin to avoid it appearing in /proc/cmdline.
func (k *K8sClient) WGAddPeer(ctx context.Context, pubKey, psk, allowedIPs string) error {
	cmd := []string{"wg", "set", "wg0", "peer", pubKey, "preshared-key", "/dev/stdin", "allowed-ips", allowedIPs}
	return k.execInWGPod(ctx, cmd, strings.NewReader(psk+"\n"))
}

// WGRemovePeer hot-removes a peer from the running WireGuard instance.
func (k *K8sClient) WGRemovePeer(ctx context.Context, pubKey string) error {
	return k.execInWGPod(ctx, []string{"wg", "set", "wg0", "peer", pubKey, "remove"}, nil)
}

// WGSetAllowedIPs updates the allowed-ips for an existing peer without touching the PSK.
func (k *K8sClient) WGSetAllowedIPs(ctx context.Context, pubKey, allowedIPs string) error {
	return k.execInWGPod(ctx, []string{"wg", "set", "wg0", "peer", pubKey, "allowed-ips", allowedIPs}, nil)
}

// WGShowDump returns the output of `wg show wg0 dump` from the running WireGuard pod.
func (k *K8sClient) WGShowDump(ctx context.Context) (string, error) {
	return k.runInWGPod(ctx, []string{"wg", "show", "wg0", "dump"}, nil)
}

func (k *K8sClient) execInWGPod(ctx context.Context, cmd []string, stdin io.Reader) error {
	_, err := k.runInWGPod(ctx, cmd, stdin)
	return err
}

func (k *K8sClient) runInWGPod(ctx context.Context, cmd []string, stdin io.Reader) (string, error) {
	pods, err := k.client.CoreV1().Pods(k.namespace).List(ctx, metav1.ListOptions{
		LabelSelector: "app=wireguard",
	})
	if err != nil {
		return "", fmt.Errorf("list pods: %w", err)
	}
	if len(pods.Items) == 0 {
		return "", fmt.Errorf("no wireguard pod found in namespace %s", k.namespace)
	}

	req := k.client.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(pods.Items[0].Name).
		Namespace(k.namespace).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Command: cmd,
			Stdin:   stdin != nil,
			Stdout:  true,
			Stderr:  true,
		}, scheme.ParameterCodec)

	executor, err := remotecommand.NewSPDYExecutor(k.config, "POST", req.URL())
	if err != nil {
		return "", fmt.Errorf("create executor: %w", err)
	}

	var stdout, stderr bytes.Buffer
	if err = executor.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdin:  stdin,
		Stdout: &stdout,
		Stderr: &stderr,
	}); err != nil {
		return "", fmt.Errorf("exec: %w (stderr: %s)", err, stderr.String())
	}
	return stdout.String(), nil
}
