/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_calculate.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/04/18 19:04:55 by jchiang-          #+#    #+#             */
/*   Updated: 2019/04/18 19:25:57 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"

int			hash_calculate(t_ssl *ssl, char *hash)
{
	(ft_strcmp("md5", hash) == 0) && ssl_md5_init(ssl);
	(ft_strcmp("sha256", hash) == 0) && ssl_sha256_init(ssl);
	return (0);
}
