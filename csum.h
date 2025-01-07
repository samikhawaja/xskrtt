/* SPDX-License-Identifier: GPL-2.0 */

#pragma once

#include <assert.h>

static __u16 csum_fold(__u32 csum)
{
	csum = (csum & 0xffff) + (csum >> 16);
	csum = (csum & 0xffff) + (csum >> 16);

	return (__u16)~csum;
}

static inline __sum16 csum_ipv6_magic(const struct in6_addr *saddr,
				      const struct in6_addr *daddr,
					__u32 len, __u8 proto,
					__wsum csum)
{
	__u64 s = csum;
	int i;

	for (i = 0; i < 4; i++)
		s += (__u32)saddr->s6_addr32[i];
	for (i = 0; i < 4; i++)
		s += (__u32)daddr->s6_addr32[i];
	s += htons(proto + len);
	s = (s & 0xffffffff) + (s >> 32);
	s = (s & 0xffffffff) + (s >> 32);

	return csum_fold((__u32)s);
}

static inline __u16 csum_partial(const void *buff, int len, __u16 wsum)
{
	const void *end = buff + len;
	__u32 ret = 0;
	__u32 c = 0;
	__u32 n;

	assert(len >= 4);

	do {
		n = *(__u32 *)buff;
		buff += sizeof(__u32);
		ret += c;
		ret += n;
		c = (n > ret);
	} while (buff < end);

	ret += c;
	ret = (ret & 0xffff) + (ret >> 16);
	ret = (ret & 0xffff) + (ret >> 16);
	ret = (ret & 0xffff) + (ret >> 16);

	return ret;
}
