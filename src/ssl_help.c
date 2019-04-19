/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_help.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/04/16 18:56:35 by jchiang-          #+#    #+#             */
/*   Updated: 2019/04/18 19:29:55 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"

int				mini_gnl(t_ssl *ssl, char *hash)
{
	int		ret;
	char	*temp;
	char	*str;
	char	buff[2];

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
	return (1);
}

int				initiate_p(t_ssl *ssl, char *hash)
{
	int		stop;

	stop = ssl->p_flg;
	while (stop)
	{
		if (stop == ssl->p_flg)
			mini_gnl(ssl);
		ft_strdel(&ssl->msg);
		ssl->msg = ft_strdup(ssl->name);
		stop -= 1;
	}
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
