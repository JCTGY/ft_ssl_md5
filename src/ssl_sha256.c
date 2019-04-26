/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_sha256.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/04/26 12:18:34 by jchiang-          #+#    #+#             */
/*   Updated: 2019/04/26 16:46:33 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_sha256.h"

static void		sha256_arg(uint32_t *w, t_sha256 *sha)
{
	int			i;
	uint32_t	ch;
	uint32_t	maj;
	uint32_t	s0;
	uint32_t	s1;

	i = -1;
	sha256_addstart(sha);
	while (++i < 64)
	{
		s1 = (u32_rr(sha->e, 6)) ^ (u32_rr(sha->e, 11)) ^ (u32_rr(sha->e, 25));
		ch = (sha->e & sha->f) ^ ((~sha->e) & sha->g);
		sha->t1 = sha->h + s1 + ch + g_sha256_k[i] + w[i];
		s0 = (u32_rr(sha->a, 2)) ^ (u32_rr(sha->a, 13)) ^ (u32_rr(sha->a, 22));
		maj = (sha->a & sha->b) ^ (sha->a & sha->c) ^ (sha->b & sha->c);
		sha->t2 = s0 + maj;
		sha->h = sha->g;
        sha->g = sha->f;
        sha->f = sha->e;
        sha->e = sha->d + sha->t1;
        sha->d = sha->c;
        sha->c = sha->b;
        sha->b = sha->a;
        sha->a = sha->t1 +sha->t2;
	}
	sha256_addback(sha);
}

static void		sha256_transform(t_sha256 *sha)
{
	uint32_t	chunk;
	uint32_t	*w;

	sha->h0 = 0x6a09e667;
	sha->h1 = 0xbb67ae85;
	sha->h2 = 0x3c6ef372;
	sha->h3 = 0xa54ff53a;
	sha->h4 = 0x510e527f;
	sha->h5 = 0x9b05688c;
	sha->h6 = 0x1f83d9ab;
	sha->h7 = 0x5be0cd19;
	chunk = 0;
	while (chunk < sha->msg_len)
	{
		w = sha256_input((uint32_t*)(sha->msg + chunk));
		sha256_arg(w, sha);
		chunk = chunk + 64;
	}
}

static void		sha256_padding(uint8_t *msg, size_t len, t_sha256 *sha)
{
	size_t		i;

	sha->msg_len = len * 8 + 1;
	while (sha->msg_len % 512 != 448)
		sha->msg_len++;
	if (!(sha->msg = ft_memalloc(sha->msg_len + 64)))
		return ;
	ft_strcpy((char *)sha->msg, (const char *)msg);
	sha->msg_len /= 8;
	i = len;
	sha->msg[i] = 128;
	while (++i < sha->msg_len)
		sha->msg[i] = 0;
	*(uint32_t*)(sha->msg + i) = (uint32_t)len * 8;
}


int			ssl_sha256_init(uint8_t *msg, size_t len, t_ssl *ssl)
{
	t_sha256		sha;

	ft_bzero(&sha, sizeof(t_sha256));
	sha256_padding(msg, len, &sha);
	sha256_transform(&sha);
	ft_printf("%s\n", ssl->name);
	ft_printf("%x\n%x\n%x\n%x\n%x\n%x\n%x\n%x\n", sha.h0, sha.h1, sha.h2, sha.h3, sha.h4, sha.h5, sha.h6, sha.h7);
	return (0);
}
