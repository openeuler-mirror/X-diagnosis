/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/* THIS FILE IS AUTOGENERATED! */
#ifndef __XD_SCSIIOCOUNT_BPF_SKEL_H__
#define __XD_SCSIIOCOUNT_BPF_SKEL_H__

#include <stdlib.h>
#include <bpf/libbpf.h>

struct xd_scsiiocount_bpf {
	struct bpf_object_skeleton *skeleton;
	struct bpf_object *obj;
	struct {
		struct bpf_map *filter_sdev_map;
		struct bpf_map *scsi_opcode_map;
	} maps;
	struct {
		struct bpf_program *scsi_dispatch_cmd_start;
	} progs;
	struct {
		struct bpf_link *scsi_dispatch_cmd_start;
	} links;
};

static void
xd_scsiiocount_bpf__destroy(struct xd_scsiiocount_bpf *obj)
{
	if (!obj)
		return;
	if (obj->skeleton)
		bpf_object__destroy_skeleton(obj->skeleton);
	free(obj);
}

static inline int
xd_scsiiocount_bpf__create_skeleton(struct xd_scsiiocount_bpf *obj);

static inline struct xd_scsiiocount_bpf *
xd_scsiiocount_bpf__open_opts(const struct bpf_object_open_opts *opts)
{
	struct xd_scsiiocount_bpf *obj;

	obj = (struct xd_scsiiocount_bpf *)calloc(1, sizeof(*obj));
	if (!obj)
		return NULL;
	if (xd_scsiiocount_bpf__create_skeleton(obj))
		goto err;
	if (bpf_object__open_skeleton(obj->skeleton, opts))
		goto err;

	return obj;
err:
	xd_scsiiocount_bpf__destroy(obj);
	return NULL;
}

static inline struct xd_scsiiocount_bpf *
xd_scsiiocount_bpf__open(void)
{
	return xd_scsiiocount_bpf__open_opts(NULL);
}

static inline int
xd_scsiiocount_bpf__load(struct xd_scsiiocount_bpf *obj)
{
	return bpf_object__load_skeleton(obj->skeleton);
}

static inline struct xd_scsiiocount_bpf *
xd_scsiiocount_bpf__open_and_load(void)
{
	struct xd_scsiiocount_bpf *obj;

	obj = xd_scsiiocount_bpf__open();
	if (!obj)
		return NULL;
	if (xd_scsiiocount_bpf__load(obj)) {
		xd_scsiiocount_bpf__destroy(obj);
		return NULL;
	}
	return obj;
}

static inline int
xd_scsiiocount_bpf__attach(struct xd_scsiiocount_bpf *obj)
{
	return bpf_object__attach_skeleton(obj->skeleton);
}

static inline void
xd_scsiiocount_bpf__detach(struct xd_scsiiocount_bpf *obj)
{
	return bpf_object__detach_skeleton(obj->skeleton);
}

static inline int
xd_scsiiocount_bpf__create_skeleton(struct xd_scsiiocount_bpf *obj)
{
	struct bpf_object_skeleton *s;

	s = (struct bpf_object_skeleton *)calloc(1, sizeof(*s));
	if (!s)
		return -1;
	obj->skeleton = s;

	s->sz = sizeof(*s);
	s->name = "xd_scsiiocount_bpf";
	s->obj = &obj->obj;

	/* maps */
	s->map_cnt = 2;
	s->map_skel_sz = sizeof(*s->maps);
	s->maps = (struct bpf_map_skeleton *)calloc(s->map_cnt, s->map_skel_sz);
	if (!s->maps)
		goto err;

	s->maps[0].name = "filter_sdev_map";
	s->maps[0].map = &obj->maps.filter_sdev_map;

	s->maps[1].name = "scsi_opcode_map";
	s->maps[1].map = &obj->maps.scsi_opcode_map;

	/* programs */
	s->prog_cnt = 1;
	s->prog_skel_sz = sizeof(*s->progs);
	s->progs = (struct bpf_prog_skeleton *)calloc(s->prog_cnt, s->prog_skel_sz);
	if (!s->progs)
		goto err;

	s->progs[0].name = "scsi_dispatch_cmd_start";
	s->progs[0].prog = &obj->progs.scsi_dispatch_cmd_start;
	s->progs[0].link = &obj->links.scsi_dispatch_cmd_start;

	s->data_sz = 4872;
	s->data = (void *)"\
\x7f\x45\x4c\x46\x02\x01\x01\0\0\0\0\0\0\0\0\0\x01\0\xf7\0\x01\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\xc8\x0f\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\x40\0\x0d\0\
\x0c\0\xbf\x16\0\0\0\0\0\0\xb7\x01\0\0\x01\0\0\0\x63\x1a\xe4\xff\0\0\0\0\x63\
\x1a\xe0\xff\0\0\0\0\xbf\xa2\0\0\0\0\0\0\x07\x02\0\0\xe4\xff\xff\xff\x18\x01\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\x85\0\0\0\x01\0\0\0\x55\0\x05\0\0\0\0\0\x61\x64\x14\
\0\0\0\0\0\x61\x63\x10\0\0\0\0\0\x61\x62\x0c\0\0\0\0\0\x61\x61\x08\0\0\0\0\0\
\x05\0\x0c\0\0\0\0\0\x61\x01\0\0\0\0\0\0\x61\x62\x08\0\0\0\0\0\x5d\x21\x20\0\0\
\0\0\0\x61\x02\x04\0\0\0\0\0\x61\x63\x0c\0\0\0\0\0\x5d\x32\x1d\0\0\0\0\0\x61\
\x03\x08\0\0\0\0\0\x61\x64\x10\0\0\0\0\0\x5d\x43\x1a\0\0\0\0\0\x61\x04\x0c\0\0\
\0\0\0\x61\x65\x14\0\0\0\0\0\x5d\x54\x17\0\0\0\0\0\x63\x4a\xf4\xff\0\0\0\0\x63\
\x3a\xf0\xff\0\0\0\0\x63\x2a\xec\xff\0\0\0\0\x63\x1a\xe8\xff\0\0\0\0\x61\x61\
\x18\0\0\0\0\0\x63\x1a\xf8\xff\0\0\0\0\xbf\xa2\0\0\0\0\0\0\x07\x02\0\0\xe8\xff\
\xff\xff\x18\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x85\0\0\0\x01\0\0\0\x15\0\x03\0\0\
\0\0\0\xb7\x01\0\0\x01\0\0\0\xc3\x10\0\0\0\0\0\0\x05\0\x08\0\0\0\0\0\xbf\xa2\0\
\0\0\0\0\0\x07\x02\0\0\xe8\xff\xff\xff\xbf\xa3\0\0\0\0\0\0\x07\x03\0\0\xe0\xff\
\xff\xff\x18\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb7\x04\0\0\0\0\0\0\x85\0\0\0\x02\
\0\0\0\xb7\0\0\0\0\0\0\0\x95\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\x47\x50\x4c\0\x9f\xeb\x01\0\x18\0\0\0\0\0\0\0\x98\x02\0\0\x98\
\x02\0\0\x39\x04\0\0\0\0\0\0\0\0\0\x02\x03\0\0\0\x01\0\0\0\0\0\0\x01\x04\0\0\0\
\x20\0\0\x01\0\0\0\0\0\0\0\x03\0\0\0\0\x02\0\0\0\x04\0\0\0\x01\0\0\0\x05\0\0\0\
\0\0\0\x01\x04\0\0\0\x20\0\0\0\0\0\0\0\0\0\0\x02\x06\0\0\0\x19\0\0\0\0\0\0\x08\
\x07\0\0\0\x1d\0\0\0\0\0\0\x08\x08\0\0\0\x23\0\0\0\0\0\0\x01\x04\0\0\0\x20\0\0\
\0\0\0\0\0\0\0\0\x02\x0a\0\0\0\x30\0\0\0\x04\0\0\x04\x10\0\0\0\x3a\0\0\0\x08\0\
\0\0\0\0\0\0\x3f\0\0\0\x08\0\0\0\x20\0\0\0\x47\0\0\0\x08\0\0\0\x40\0\0\0\x4a\0\
\0\0\x08\0\0\0\x60\0\0\0\0\0\0\0\x04\0\0\x04\x20\0\0\0\x4e\0\0\0\x01\0\0\0\0\0\
\0\0\x53\0\0\0\x05\0\0\0\x40\0\0\0\x57\0\0\0\x09\0\0\0\x80\0\0\0\x5d\0\0\0\x01\
\0\0\0\xc0\0\0\0\x69\0\0\0\0\0\0\x0e\x0b\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\x02\x0e\
\0\0\0\x79\0\0\0\x02\0\0\x04\x14\0\0\0\x82\0\0\0\x0a\0\0\0\0\0\0\0\x87\0\0\0\
\x08\0\0\0\x80\0\0\0\0\0\0\0\0\0\0\x02\x10\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\x02\
\0\0\0\x04\0\0\0\0\x10\0\0\0\0\0\0\x04\0\0\x04\x20\0\0\0\x4e\0\0\0\x01\0\0\0\0\
\0\0\0\x53\0\0\0\x0d\0\0\0\x40\0\0\0\x57\0\0\0\x05\0\0\0\x80\0\0\0\x5d\0\0\0\
\x0f\0\0\0\xc0\0\0\0\x8e\0\0\0\0\0\0\x0e\x11\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\x02\
\x14\0\0\0\x9e\0\0\0\x02\0\0\x04\x20\0\0\0\xac\0\0\0\x15\0\0\0\0\0\0\0\x53\0\0\
\0\x0e\0\0\0\x40\0\0\0\xbb\0\0\0\0\0\0\x08\x16\0\0\0\xbf\0\0\0\0\0\0\x08\x17\0\
\0\0\xc5\0\0\0\0\0\0\x01\x08\0\0\0\x40\0\0\0\0\0\0\0\x01\0\0\x0d\x02\0\0\0\xdc\
\0\0\0\x13\0\0\0\xe0\0\0\0\x01\0\0\x0c\x18\0\0\0\x1d\x04\0\0\0\0\0\x01\x01\0\0\
\0\x08\0\0\x01\0\0\0\0\0\0\0\x03\0\0\0\0\x1a\0\0\0\x04\0\0\0\x04\0\0\0\x22\x04\
\0\0\0\0\0\x0e\x1b\0\0\0\x01\0\0\0\x2b\x04\0\0\x02\0\0\x0f\0\0\0\0\x0c\0\0\0\0\
\0\0\0\x20\0\0\0\x12\0\0\0\0\0\0\0\x20\0\0\0\x31\x04\0\0\x01\0\0\x0f\0\0\0\0\
\x1c\0\0\0\0\0\0\0\x04\0\0\0\0\x69\x6e\x74\0\x5f\x5f\x41\x52\x52\x41\x59\x5f\
\x53\x49\x5a\x45\x5f\x54\x59\x50\x45\x5f\x5f\0\x75\x33\x32\0\x5f\x5f\x75\x33\
\x32\0\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x69\x6e\x74\0\x73\x64\x65\x76\x5f\
\x68\x63\x74\x6c\0\x68\x6f\x73\x74\0\x63\x68\x61\x6e\x6e\x65\x6c\0\x69\x64\0\
\x6c\x75\x6e\0\x74\x79\x70\x65\0\x6b\x65\x79\0\x76\x61\x6c\x75\x65\0\x6d\x61\
\x78\x5f\x65\x6e\x74\x72\x69\x65\x73\0\x66\x69\x6c\x74\x65\x72\x5f\x73\x64\x65\
\x76\x5f\x6d\x61\x70\0\x73\x63\x73\x69\x5f\x6b\x65\x79\0\x68\x63\x74\x6c\0\x6f\
\x70\x63\x6f\x64\x65\0\x73\x63\x73\x69\x5f\x6f\x70\x63\x6f\x64\x65\x5f\x6d\x61\
\x70\0\x73\x63\x73\x69\x5f\x63\x6d\x6e\x64\x5f\x63\x74\x78\0\x5f\x5f\x64\x6f\
\x5f\x6e\x6f\x74\x5f\x75\x73\x65\x5f\x5f\0\x75\x36\x34\0\x5f\x5f\x75\x36\x34\0\
\x6c\x6f\x6e\x67\x20\x6c\x6f\x6e\x67\x20\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\
\x69\x6e\x74\0\x63\x74\x78\0\x73\x63\x73\x69\x5f\x64\x69\x73\x70\x61\x74\x63\
\x68\x5f\x63\x6d\x64\x5f\x73\x74\x61\x72\x74\0\x74\x72\x61\x63\x65\x70\x6f\x69\
\x6e\x74\x2f\x73\x63\x73\x69\x2f\x73\x63\x73\x69\x5f\x64\x69\x73\x70\x61\x74\
\x63\x68\x5f\x63\x6d\x64\x5f\x73\x74\x61\x72\x74\0\x2f\x68\x6f\x6d\x65\x2f\x78\
\x64\x5f\x6e\x65\x77\x2f\x78\x64\x69\x61\x67\x6e\x6f\x73\x65\x2d\x31\x2e\x30\
\x2e\x31\x2f\x78\x64\x69\x61\x67\x5f\x65\x62\x70\x66\x2f\x73\x72\x63\x2f\x69\
\x6f\x2f\x78\x64\x5f\x73\x63\x73\x69\x69\x6f\x63\x6f\x75\x6e\x74\x2f\x78\x64\
\x5f\x73\x63\x73\x69\x69\x6f\x63\x6f\x75\x6e\x74\x2e\x62\x70\x66\x2e\x63\0\x69\
\x6e\x74\x20\x73\x63\x73\x69\x5f\x64\x69\x73\x70\x61\x74\x63\x68\x5f\x63\x6d\
\x64\x5f\x73\x74\x61\x72\x74\x28\x73\x74\x72\x75\x63\x74\x20\x73\x63\x73\x69\
\x5f\x63\x6d\x6e\x64\x5f\x63\x74\x78\x20\x2a\x63\x74\x78\x29\0\x09\x69\x6e\x74\
\x20\x65\x6e\x61\x62\x6c\x65\x20\x3d\x20\x31\x3b\0\x09\x69\x6e\x74\x20\x64\x65\
\x66\x5f\x76\x61\x6c\x75\x65\x20\x3d\x20\x31\x3b\0\x09\x66\x69\x6c\x74\x65\x72\
\x20\x3d\x20\x62\x70\x66\x5f\x6d\x61\x70\x5f\x6c\x6f\x6f\x6b\x75\x70\x5f\x65\
\x6c\x65\x6d\x28\x26\x66\x69\x6c\x74\x65\x72\x5f\x73\x64\x65\x76\x5f\x6d\x61\
\x70\x2c\x20\x26\x65\x6e\x61\x62\x6c\x65\x29\x3b\0\x09\x69\x66\x20\x28\x66\x69\
\x6c\x74\x65\x72\x20\x26\x26\x20\x28\x66\x69\x6c\x74\x65\x72\x2d\x3e\x68\x6f\
\x73\x74\x20\x21\x3d\x20\x63\x74\x78\x2d\x3e\x6b\x65\x79\x2e\x68\x63\x74\x6c\
\x2e\x68\x6f\x73\x74\x20\x7c\x7c\0\x20\x20\x20\x20\x20\x20\x20\x20\x6b\x65\x79\
\x2e\x68\x63\x74\x6c\x2e\x6c\x75\x6e\x20\x3d\x20\x63\x74\x78\x2d\x3e\x6b\x65\
\x79\x2e\x68\x63\x74\x6c\x2e\x6c\x75\x6e\x3b\0\x09\x6b\x65\x79\x2e\x68\x63\x74\
\x6c\x2e\x69\x64\x20\x3d\x20\x63\x74\x78\x2d\x3e\x6b\x65\x79\x2e\x68\x63\x74\
\x6c\x2e\x69\x64\x3b\0\x09\x6b\x65\x79\x2e\x68\x63\x74\x6c\x2e\x63\x68\x61\x6e\
\x6e\x65\x6c\x20\x3d\x20\x63\x74\x78\x2d\x3e\x6b\x65\x79\x2e\x68\x63\x74\x6c\
\x2e\x63\x68\x61\x6e\x6e\x65\x6c\x3b\0\x09\x6b\x65\x79\x2e\x68\x63\x74\x6c\x2e\
\x68\x6f\x73\x74\x20\x3d\x20\x63\x74\x78\x2d\x3e\x6b\x65\x79\x2e\x68\x63\x74\
\x6c\x2e\x68\x6f\x73\x74\x3b\0\x09\x09\x66\x69\x6c\x74\x65\x72\x2d\x3e\x63\x68\
\x61\x6e\x6e\x65\x6c\x20\x21\x3d\x20\x63\x74\x78\x2d\x3e\x6b\x65\x79\x2e\x68\
\x63\x74\x6c\x2e\x63\x68\x61\x6e\x6e\x65\x6c\x20\x7c\x7c\0\x09\x09\x66\x69\x6c\
\x74\x65\x72\x2d\x3e\x69\x64\x20\x21\x3d\x20\x63\x74\x78\x2d\x3e\x6b\x65\x79\
\x2e\x68\x63\x74\x6c\x2e\x69\x64\x20\x7c\x7c\0\x09\x09\x66\x69\x6c\x74\x65\x72\
\x2d\x3e\x6c\x75\x6e\x20\x21\x3d\x20\x63\x74\x78\x2d\x3e\x6b\x65\x79\x2e\x68\
\x63\x74\x6c\x2e\x6c\x75\x6e\x29\x29\x20\x7b\0\x09\x6b\x65\x79\x2e\x6f\x70\x63\
\x6f\x64\x65\x20\x3d\x20\x63\x74\x78\x2d\x3e\x6b\x65\x79\x2e\x6f\x70\x63\x6f\
\x64\x65\x3b\0\x09\x63\x6f\x75\x6e\x74\x20\x3d\x20\x62\x70\x66\x5f\x6d\x61\x70\
\x5f\x6c\x6f\x6f\x6b\x75\x70\x5f\x65\x6c\x65\x6d\x28\x26\x73\x63\x73\x69\x5f\
\x6f\x70\x63\x6f\x64\x65\x5f\x6d\x61\x70\x2c\x20\x26\x6b\x65\x79\x29\x3b\0\x09\
\x69\x66\x20\x28\x63\x6f\x75\x6e\x74\x29\x20\0\x09\x09\x5f\x5f\x73\x79\x6e\x63\
\x5f\x66\x65\x74\x63\x68\x5f\x61\x6e\x64\x5f\x61\x64\x64\x28\x63\x6f\x75\x6e\
\x74\x2c\x20\x31\x29\x3b\0\x09\x09\x62\x70\x66\x5f\x6d\x61\x70\x5f\x75\x70\x64\
\x61\x74\x65\x5f\x65\x6c\x65\x6d\x28\x26\x73\x63\x73\x69\x5f\x6f\x70\x63\x6f\
\x64\x65\x5f\x6d\x61\x70\x2c\x20\x26\x6b\x65\x79\x2c\x20\x26\x64\x65\x66\x5f\
\x76\x61\x6c\x75\x65\x2c\x20\x42\x50\x46\x5f\x41\x4e\x59\x29\x3b\0\x7d\0\x63\
\x68\x61\x72\0\x5f\x6c\x69\x63\x65\x6e\x73\x65\0\x2e\x6d\x61\x70\x73\0\x6c\x69\
\x63\x65\x6e\x73\x65\0\x9f\xeb\x01\0\x20\0\0\0\0\0\0\0\x14\0\0\0\x14\0\0\0\x3c\
\x02\0\0\x50\x02\0\0\0\0\0\0\x08\0\0\0\xf8\0\0\0\x01\0\0\0\0\0\0\0\x19\0\0\0\
\x10\0\0\0\xf8\0\0\0\x23\0\0\0\0\0\0\0\x20\x01\0\0\x73\x01\0\0\0\x70\0\0\x10\0\
\0\0\x20\x01\0\0\xaa\x01\0\0\x06\x84\0\0\x18\0\0\0\x20\x01\0\0\xbb\x01\0\0\x06\
\x88\0\0\x28\0\0\0\x20\x01\0\0\0\0\0\0\0\0\0\0\x30\0\0\0\x20\x01\0\0\xcf\x01\0\
\0\x0b\x90\0\0\x48\0\0\0\x20\x01\0\0\x09\x02\0\0\x0d\x94\0\0\x50\0\0\0\x20\x01\
\0\0\x3f\x02\0\0\x26\xbc\0\0\x58\0\0\0\x20\x01\0\0\x69\x02\0\0\x1e\xb8\0\0\x60\
\0\0\0\x20\x01\0\0\x8a\x02\0\0\x23\xb4\0\0\x68\0\0\0\x20\x01\0\0\xb5\x02\0\0\
\x20\xb0\0\0\x78\0\0\0\x20\x01\0\0\x09\x02\0\0\x19\x94\0\0\x80\0\0\0\x20\x01\0\
\0\x09\x02\0\0\x2f\x94\0\0\x88\0\0\0\x20\x01\0\0\x09\x02\0\0\x34\x94\0\0\x90\0\
\0\0\x20\x01\0\0\xda\x02\0\0\x0b\x98\0\0\x98\0\0\0\x20\x01\0\0\xda\x02\0\0\x24\
\x98\0\0\xa0\0\0\0\x20\x01\0\0\xda\x02\0\0\x2c\x98\0\0\xa8\0\0\0\x20\x01\0\0\
\x08\x03\0\0\x0b\x9c\0\0\xb0\0\0\0\x20\x01\0\0\x08\x03\0\0\x1f\x9c\0\0\xb8\0\0\
\0\x20\x01\0\0\x08\x03\0\0\x22\x9c\0\0\xc0\0\0\0\x20\x01\0\0\x2c\x03\0\0\x0b\
\xa0\0\0\xc8\0\0\0\x20\x01\0\0\x2c\x03\0\0\x20\xa0\0\0\xd0\0\0\0\x20\x01\0\0\
\x09\x02\0\0\x06\x94\0\0\xd8\0\0\0\x20\x01\0\0\x3f\x02\0\0\x16\xbc\0\0\xe0\0\0\
\0\x20\x01\0\0\x69\x02\0\0\x0e\xb8\0\0\xe8\0\0\0\x20\x01\0\0\x8a\x02\0\0\x13\
\xb4\0\0\xf0\0\0\0\x20\x01\0\0\xb5\x02\0\0\x10\xb0\0\0\xf8\0\0\0\x20\x01\0\0\
\x53\x03\0\0\x18\xc0\0\0\0\x01\0\0\x20\x01\0\0\x53\x03\0\0\x0d\xc0\0\0\x10\x01\
\0\0\x20\x01\0\0\x3f\x02\0\0\x16\xbc\0\0\x18\x01\0\0\x20\x01\0\0\x72\x03\0\0\
\x0a\xc8\0\0\x30\x01\0\0\x20\x01\0\0\xa8\x03\0\0\x06\xcc\0\0\x40\x01\0\0\x20\
\x01\0\0\xb5\x03\0\0\x03\xd0\0\0\x58\x01\0\0\x20\x01\0\0\0\0\0\0\0\0\0\0\x70\
\x01\0\0\x20\x01\0\0\xd7\x03\0\0\x03\xd8\0\0\x90\x01\0\0\x20\x01\0\0\x1b\x04\0\
\0\x01\xe4\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xab\0\0\0\
\0\0\x02\0\x78\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xa4\0\0\0\0\0\x02\0\xd8\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\x9d\0\0\0\0\0\x02\0\x50\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x96\0\0\0\0\0\x02\0\x90\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x02\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x74\0\0\0\x11\0\x04\0\0\0\0\0\0\0\0\0\x04\0\0\0\
\0\0\0\0\x46\0\0\0\x11\0\x03\0\0\0\0\0\0\0\0\0\x20\0\0\0\0\0\0\0\x28\0\0\0\x12\
\0\x02\0\0\0\0\0\0\0\0\0\xa0\x01\0\0\0\0\0\0\x56\0\0\0\x11\0\x03\0\x20\0\0\0\0\
\0\0\0\x20\0\0\0\0\0\0\0\x30\0\0\0\0\0\0\0\x01\0\0\0\x07\0\0\0\x18\x01\0\0\0\0\
\0\0\x01\0\0\0\x09\0\0\0\x70\x01\0\0\0\0\0\0\x01\0\0\0\x09\0\0\0\x84\x02\0\0\0\
\0\0\0\0\0\0\0\x07\0\0\0\x90\x02\0\0\0\0\0\0\0\0\0\0\x09\0\0\0\xa8\x02\0\0\0\0\
\0\0\0\0\0\0\x06\0\0\0\x2c\0\0\0\0\0\0\0\0\0\0\0\x05\0\0\0\x40\0\0\0\0\0\0\0\0\
\0\0\0\x05\0\0\0\x50\0\0\0\0\0\0\0\0\0\0\0\x05\0\0\0\x60\0\0\0\0\0\0\0\0\0\0\0\
\x05\0\0\0\x70\0\0\0\0\0\0\0\0\0\0\0\x05\0\0\0\x80\0\0\0\0\0\0\0\0\0\0\0\x05\0\
\0\0\x90\0\0\0\0\0\0\0\0\0\0\0\x05\0\0\0\xa0\0\0\0\0\0\0\0\0\0\0\0\x05\0\0\0\
\xb0\0\0\0\0\0\0\0\0\0\0\0\x05\0\0\0\xc0\0\0\0\0\0\0\0\0\0\0\0\x05\0\0\0\xd0\0\
\0\0\0\0\0\0\0\0\0\0\x05\0\0\0\xe0\0\0\0\0\0\0\0\0\0\0\0\x05\0\0\0\xf0\0\0\0\0\
\0\0\0\0\0\0\0\x05\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\x05\0\0\0\x10\x01\0\0\0\0\0\
\0\0\0\0\0\x05\0\0\0\x20\x01\0\0\0\0\0\0\0\0\0\0\x05\0\0\0\x30\x01\0\0\0\0\0\0\
\0\0\0\0\x05\0\0\0\x40\x01\0\0\0\0\0\0\0\0\0\0\x05\0\0\0\x50\x01\0\0\0\0\0\0\0\
\0\0\0\x05\0\0\0\x60\x01\0\0\0\0\0\0\0\0\0\0\x05\0\0\0\x70\x01\0\0\0\0\0\0\0\0\
\0\0\x05\0\0\0\x80\x01\0\0\0\0\0\0\0\0\0\0\x05\0\0\0\x90\x01\0\0\0\0\0\0\0\0\0\
\0\x05\0\0\0\xa0\x01\0\0\0\0\0\0\0\0\0\0\x05\0\0\0\xb0\x01\0\0\0\0\0\0\0\0\0\0\
\x05\0\0\0\xc0\x01\0\0\0\0\0\0\0\0\0\0\x05\0\0\0\xd0\x01\0\0\0\0\0\0\0\0\0\0\
\x05\0\0\0\xe0\x01\0\0\0\0\0\0\0\0\0\0\x05\0\0\0\xf0\x01\0\0\0\0\0\0\0\0\0\0\
\x05\0\0\0\0\x02\0\0\0\0\0\0\0\0\0\0\x05\0\0\0\x10\x02\0\0\0\0\0\0\0\0\0\0\x05\
\0\0\0\x20\x02\0\0\0\0\0\0\0\0\0\0\x05\0\0\0\x30\x02\0\0\0\0\0\0\0\0\0\0\x05\0\
\0\0\x40\x02\0\0\0\0\0\0\0\0\0\0\x05\0\0\0\x50\x02\0\0\0\0\0\0\0\0\0\0\x05\0\0\
\0\x60\x02\0\0\0\0\0\0\0\0\0\0\x05\0\0\0\x0e\x0d\x0f\x0c\0\x2e\x74\x65\x78\x74\
\0\x2e\x72\x65\x6c\x2e\x42\x54\x46\x2e\x65\x78\x74\0\x2e\x72\x65\x6c\x74\x72\
\x61\x63\x65\x70\x6f\x69\x6e\x74\x2f\x73\x63\x73\x69\x2f\x73\x63\x73\x69\x5f\
\x64\x69\x73\x70\x61\x74\x63\x68\x5f\x63\x6d\x64\x5f\x73\x74\x61\x72\x74\0\x2e\
\x6d\x61\x70\x73\0\x66\x69\x6c\x74\x65\x72\x5f\x73\x64\x65\x76\x5f\x6d\x61\x70\
\0\x73\x63\x73\x69\x5f\x6f\x70\x63\x6f\x64\x65\x5f\x6d\x61\x70\0\x2e\x6c\x6c\
\x76\x6d\x5f\x61\x64\x64\x72\x73\x69\x67\0\x5f\x6c\x69\x63\x65\x6e\x73\x65\0\
\x2e\x73\x74\x72\x74\x61\x62\0\x2e\x73\x79\x6d\x74\x61\x62\0\x2e\x72\x65\x6c\
\x2e\x42\x54\x46\0\x4c\x42\x42\x30\x5f\x39\0\x4c\x42\x42\x30\x5f\x38\0\x4c\x42\
\x42\x30\x5f\x36\0\x4c\x42\x42\x30\x5f\x32\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\x01\0\0\0\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\x18\0\0\0\x01\0\0\0\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\xa0\
\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\
\x01\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xe0\x01\0\0\0\0\0\0\x40\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x75\0\0\0\x01\0\0\0\x03\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x20\x02\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x91\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\x24\x02\0\0\0\0\0\0\xe9\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\x0b\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x0d\x09\0\0\0\0\0\0\x70\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\x85\0\0\0\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x80\x0b\0\0\0\
\0\0\0\xf0\0\0\0\0\0\0\0\x0c\0\0\0\x06\0\0\0\x08\0\0\0\0\0\0\0\x18\0\0\0\0\0\0\
\0\x14\0\0\0\x09\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x70\x0c\0\0\0\0\0\0\x30\
\0\0\0\0\0\0\0\x07\0\0\0\x02\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x8d\0\0\
\0\x09\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xa0\x0c\0\0\0\0\0\0\x30\0\0\0\0\0\
\0\0\x07\0\0\0\x05\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x07\0\0\0\x09\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xd0\x0c\0\0\0\0\0\0\x40\x02\0\0\0\0\0\0\x07\
\0\0\0\x06\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x66\0\0\0\x03\x4c\xff\x6f\
\0\0\0\x80\0\0\0\0\0\0\0\0\0\0\0\0\x10\x0f\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x7d\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\x14\x0f\0\0\0\0\0\0\xb2\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

	return 0;
err:
	bpf_object__destroy_skeleton(s);
	return -1;
}

#endif /* __XD_SCSIIOCOUNT_BPF_SKEL_H__ */