/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_sha256.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/04/26 12:18:34 by jchiang-          #+#    #+#             */
/*   Updated: 2019/04/27 16:32:09 by jchiang-         ###   ########.fr       */
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
	w = 0;
//	ft_printf("||%s||\n", w);
//	ft_printf("%x\n%x\n%x\n%x\n%x\n%x\n%x\n%x\n", sha->a, sha->b, sha->c, sha->d, sha->e, sha->f, sha->g, sha->h);
	while (++i < 64)
	{
		s1 = (u32_rr(sha->e, 6)) ^ (u32_rr(sha->e, 11)) ^ (u32_rr(sha->e, 25));
		ch = (sha->e & sha->f) ^ ((~sha->e) & sha->g);
		sha->t1 = sha->h + s1 + ch + g_sha256_k[i] + sha->w[i];
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
        sha->a = sha->t1 + sha->t2;
	//	ft_printf("%x\n%x\n%x\n%x\n%x\n%x\n%x\n%x\n", sha->h0, sha->h1, sha->h2, sha->h3, sha->h4, sha->h5, sha->h6, sha->h7);
//		ft_printf("---------------------------------------------------\n");
//		ft_printf("%x\n%x\n%x\n%x\n%x\n%x\n%x\n%x\n", sha->a, sha->b, sha->c, sha->d, sha->e, sha->f, sha->g, sha->h);
	}
	sha256_addback(sha);
}

static void		sha256_transform(t_sha256 *sha)
{
	size_t		chunk;

	sha->h0 = 0x6a09e667;
	sha->h1 = 0xbb67ae85;
	sha->h2 = 0x3c6ef372;
	sha->h3 = 0xa54ff53a;
	sha->h4 = 0x510e527f;
	sha->h5 = 0x9b05688c;
	sha->h6 = 0x1f83d9ab;
	sha->h7 = 0x5be0cd19;
	chunk = 0;
	while (chunk < sha->set)
	{
		ft_printf("what is sha->set === %zu\n", sha->set);
		sha256_input(sha->msg + (chunk * 16), sha);
		sha256_arg(sha->w, sha);
		chunk += 1;
	}
}

static void		sha256_padding(uint8_t *msg, size_t len, t_sha256 *sha)
{
	size_t		i;
	size_t		s;
	uint32_t	msg_len;

	msg_len = len * 8 + 1;
	while (msg_len % 512 != 448)
		msg_len++;
	sha->set = (msg_len + 64) / 512;
	if (!(sha->msg = ft_memalloc(sizeof(uint32_t) * 16 * sha->set)))
		return ;
	ft_memcpy((char *)sha->msg, msg, len);
	((char*)sha->msg)[len] = 0x80;
	msg_len /= 8;
	i = len;
	while (++i < msg_len)
		((char*)sha->msg)[i] = 0;
	msg_len /= 2;
	s = 0;
	while (s < msg_len)
	{
		sha->msg[s] = swap_32bit((uint32_t)sha->msg[s]);
				s++;
	}
	*(sha->msg + msg_len) = (uint32_t)len * 8;
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
