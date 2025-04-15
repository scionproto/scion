// Copyright Red Hat
int create_sample_sockmap(int sock, int parse_prog_fd, int verdict_prog_fd)
{
        int index = 0;
        int map, err;

        map = bpf_map_create(BPF_MAP_TYPE_SOCKMAP, NULL, sizeof(int), sizeof(int), 1, NULL);
        if (map < 0) {
                fprintf(stderr, "Failed to create sockmap: %s\n", strerror(errno));
                return -1;
        }

        err = bpf_prog_attach(verdict_prog_fd, map, BPF_SK_SKB_VERDICT, 0);
        if (err){
                fprintf(stderr, "Failed to attach_verdict_prog_to_map: %s\n", strerror(errno));
                goto out;
        }

        err = bpf_map_update_elem(map, &index, &sock, BPF_NOEXIST);
        if (err) {
                fprintf(stderr, "Failed to update sockmap: %s\n", strerror(errno));
                goto out;
        }

out:
        close(map);
        return err;
}
