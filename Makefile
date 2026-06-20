REGISTRY  ?= YOUR_REGISTRY
IMAGE     := $(REGISTRY)/wg-manager
TAG       ?= latest
PLATFORM  ?= linux/arm64

.PHONY: build push deploy restart logs port-forward

build:
	docker buildx build --platform $(PLATFORM) -t $(IMAGE):$(TAG) --push .

push: build

deploy:
	kubectl apply -f k8s/rbac.yaml
	kubectl apply -f k8s/deployment.yaml

restart:
	kubectl -n vpn rollout restart deployment/wg-manager
	kubectl -n vpn rollout status deployment/wg-manager --timeout=120s

logs:
	kubectl -n vpn logs -l app=wg-manager -f

port-forward:
	kubectl -n vpn port-forward svc/wg-manager 8080:80
