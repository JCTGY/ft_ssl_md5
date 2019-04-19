/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_ssl.h                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jchiang- <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/04/16 18:09:02 by jchiang-          #+#    #+#             */
/*   Updated: 2019/04/18 19:29:53 by jchiang-         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef FT_SSL_H
# define FT_SSL_H

/*
** Md5 & sha256
*/

# include "../libft/includes/libft.h"
# include "../libft/includes/ft_printf.h"
# include <sys/stat.h>
# include <fcntl.h>
# include <errno.h>

# define FLAG_ERROR		(1 << 1)
# define S_NO_ARG		(1 << 2)
# define NO_FILE		(1 << 3)
# define NO_PERM		(1 << 4)
# define IS_DIR			(1 << 5)

# define SSL_P			(1 << 0)
# define SSL_S			(1 << 1)
# define SSL_R			(1 << 2)
# define SSL_Q			(1 << 3)

typedef struct			s_ssl
{
	int					flag;
	int					p_flg;
	uint32_t			h1;
	uint32_t			h2;
	uint32_t			h3;
	uint32_t			h4;
	char				*msg;
	char				*name;
}						t_ssl;

int						initiate_p(t_ssl *ssl, char *hash);
int						check_error(int argc, char **argv);
int						dis_error(char *tssl, int error, char flag, char *file);
int						mini_gnl(t_ssl *ssl, char *hash);
int						hash_calculate(t_ssl *ssl, char *hash);

#endif
