default:
	@echo "TODO help"

manual_link_setup:
	sudo ip tuntap add name braccept mode tap
	sudo ip addr add
	sudo ip link set braccept master brlocal

create:
	docker-compose -f docker-compose.yml up --no-start

up:
	#docker-compose -f go/border/border-acceptance/docker-compose.yml up --detach
	docker-compose -f docker-compose.yml up --detach

down:
	#docker-compose -f go/border/border-acceptance/docker-compose.yml down
	docker-compose -f docker-compose.yml down


alt:
	docker-compose -f docker-compose.yml up --detach dispatcher
	sudo mkdir -p /var/run/netns
	sudo ln -fs `docker inspect border-acceptance_dispatcher_1 -f '{{.NetworkSettings.SandboxKey}}'` -t /var/run/netns
	sudo ip link add veth0_cntr type veth peer name veth0_root
	sudo ip link set veth0_root up
	sudo ip link set veth0_cntr up
	NS=$$(ip netns list); \
	sudo ip link set veth0_cntr netns $$NS; \
	sudo ip netns exec $$NS ip a

ns-link:
	sudo mkdir -p /var/run/netns
	sudo ln -fs `docker inspect border-acceptance_dispatcher_1 -f '{{.NetworkSettings.SandboxKey}}'` -t /var/run/netns

clean-alt: down
	sudo rm -f /var/run/netns/*
	sudo ip link set ifid0-cont down
	sudo ip link set ifid0 down
	sudo ip link del veth0_root

