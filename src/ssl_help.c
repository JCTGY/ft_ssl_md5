/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_help.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/04/16 18:56:35 by jchiang-          #+#    #+#             */
/*   Updated: 2019/04/26 09:24:26 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"

void			del_str(t_ssl *ssl)
{
	ft_strdel(&ssl->msg);
	ft_strdel(&ssl->name);
}

int				mini_gnl(t_ssl *ssl, char *hash)
{
	int		ret;
	char	*temp;
	char	*str;
	char	buff[2];

	(!(ssl->flag & SSL_P)) && (ssl->flag |= SSL_ST);
	str = ft_strnew(1);
	ret = 0;
	buff[1] = '\0';
	while ((ret = read(0, buff, 1)) > 0)
	{
		if (ret == 0)
			break ;
		temp = str;
		str = ft_strjoin(temp, buff);
		free(temp);
	}
	ssl->name = str;
	ssl->msg = ft_strdup(ssl->name);
	hash_calculate(ssl, hash);
	return (1);
}

int				initiate_p(t_ssl *ssl, char *hash)
{
	int		stop;

	ssl->flag |= SSL_P;
	stop = ssl->p_flg;
	while (stop)
	{
		if (stop == ssl->p_flg)
			mini_gnl(ssl, hash);
		ssl->flag |= SSL_PP;
		ssl->msg = ft_strnew(0);
		ssl->name = 0;
		stop -= 1;
		(stop) && hash_calculate(ssl, hash);
	}
	ssl->flag ^= SSL_P;
	return (1);
}

int				check_error(int argc, char **argv)
{
	if (argc == 1)
	{
		ft_printf("usage: ft_ssl command [command opts] [command args]\n");
		return (0);
	}
	if (!argv[1] || (ft_strcmp(argv[1], "md5") && ft_strcmp(argv[1], "sha256")))
	{
		(argv[1]) &&
			ft_printf("ft_ssl: Error: '%s' is an invalid command\n\n", argv[1]);
		ft_printf("Standard commands:\n\n");
		ft_printf("Message Digest commands:\n");
		ft_printf("md5\nsha256\n\nCipher commands:\n");
		return (0);
	}
	return (1);
}

int				dis_error(char *tssl, int error, char flag, char *file)
{
	if (error == FLAG_ERROR)
	{
		ft_printf("%s: illegal option -- %c\n", tssl, flag);
		ft_printf("usage: %s [-pqr] [-s string] [files ...]\n", tssl);
		return (0);
	}
	else if (error == S_NO_ARG)
	{
		ft_printf("%s: option requires an argument -- %c\n", tssl, flag);
		ft_printf("usage: %s [-pqr] [-s string] [files ...]\n", tssl);
		return (0);
	}
	else if (error == NO_FILE)
		ft_printf("%s: %s: No such file or directory\n", tssl, file);
	return (0);
}
