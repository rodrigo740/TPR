# archlinux build with SSH and botnet

# get arch linux image
FROM archlinux:latest

# update the repositories
RUN pacman -Syy

# install needed packages
RUN pacman -S --noconfirm openssh vim git python

# copy botnet files into the container
COPY TPR .
COPY miniircd .

# generate host keys
RUN /usr/bin/ssh-keygen -A

# add password to root user (username:password)
RUN echo 'root:root' | chpasswd

# expose tcp ports
EXPOSE 22
EXPOSE 443  
EXPOSE 6667

# run openssh daemon
CMD ["/usr/sbin/sshd", "-D"]
