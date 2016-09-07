// NOT WORKING CODE
// Only provided to give an idea of the sequence of libhsr API calls

void handle_signal(int sig)
{
    printf("received signal %d\n", sig);
    exit(0);
}

int scion_init(int argc, char **argv)
{
    int ret = -1;

    strcpy(my_name, argv[0]);

    /* Parse topology file */
    ret = parse_topology_file(argv[1]);
    if (ret < 0) {
        fprintf(stderr, "error parsing topology file\n");
        return ret;
    }

    /* Parse config file */
    char buf[100];
    ret = parse_config_file(argv[2], buf);
    if (ret < 0) {
        fprintf(stderr, "error parsing config file\n");
        return ret;
    }
    rk.roundkey = aes_assembly_init(buf);
    rk.iv = malloc(16);

    struct sockaddr_storage addrs[3];
    memset(addrs, 0, sizeof(struct sockaddr_storage) * 3);
    // interface_addr and local_addr are of type struct OverlayAddr
    // overlay_to_sockaddr() converts them to struct sockaddr_storage
    overlay_to_sockaddr(&interface_addr, &addrs[0]);
    overlay_to_sockaddr(&local_addr, &addrs[1]);
    setup_network(addrs, 2);

    return 0;
}

int main(int argc, char **argv)
{
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    signal(SIGQUIT, handle_signal);

    int ret = router_init(argc, argv);
    argc -= ret;
    argv += ret;
    if (argc != 3 || scion_init(argc, argv) < 0) {
        zlog_fatal(zc, "invalid scion args");
        zlog_fini();
        exit(1);
    }

    pthread_t sync_thread, request_thread;
    pthread_t worker_threads[ROUTER_THREADS];
    create_lib_threads();
    pthread_create(&sync_thread, NULL, sync_interface, NULL);
    pthread_create(&request_thread, NULL, request_ifstates, NULL);
    size_t i;
    for (i = 0; i < ROUTER_THREADS; i++)
        pthread_create(&worker_threads[i], NULL, router_loop, NULL);

    /* Note: join will not actually return unless an error occurs */
    for (i = 0; i < ROUTER_THREADS; i++)
        pthread_join(worker_threads[i], NULL);
    pthread_join(sync_thread, NULL);
    pthread_join(request_thread, NULL);
    join_lib_threads();
}

void * router_loop(void *arg)
{
    RouterPacket packets[MAX_PACKETS];
    memset(packets, 0, sizeof(packets));

    while (1) {
        int i;
        int count = get_packets(packets, MAX_PACKETS);
        for (i = 0; i < count; i++)
            handle_request(&packets[i]);
    }
}
