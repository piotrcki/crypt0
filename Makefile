#   Copyright (C) 2015 Piotr Chmielnicki
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 3 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software Foundation,
#   Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA



TOCLEAN=	encrypt0/encrypt0 \
			encrypt0/encrypt0.exe \
			decrypt0/decrypt0 \
			decrypt0/decrypt0.exe \
			genpads0/genpads0 \
			genpads0/genpads0.exe

all:
	cd encrypt0 && go build encrypt0.go
	cd decrypt0 && go build decrypt0.go
	cd genpads0 && go build genpads0.go

clean:
	go clean
	rm -fv $(TOCLEAN)

fclean: clean

re: fclean all

# Linux (and *BSD ?) only
install:
	mkdir -p ~/bin/
	install encrypt0/encrypt0 \
			encrypt0/encrypt0-gui \
			decrypt0/decrypt0 \
			decrypt0/decrypt0-gui \
			genpads0/genpads0 \
			~/bin/
	mkdir -p ~/.local/share/applications/
	install encrypt0/encrypt0.desktop \
			decrypt0/decrypt0.desktop \
			~/.local/share/applications/

uninstall:
	rm -fv	~/bin/encrypt0 \
			~/bin/encrypt0-gui \
			~/bin/decrypt0 \
			~/bin/decrypt0-gui \
			~/bin/genpads0 \
			~/.local/share/applications/encrypt0.desktop \
			~/.local/share/applications/decrypt0.desktop

full: re install

purge: uninstall clean

fmt:
	go fmt encrypt0/encrypt0.go
	go fmt decrypt0/decrypt0.go
	go fmt genpads0/genpads0.go
