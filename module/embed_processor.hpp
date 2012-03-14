// elliptics-fastcgi - FastCGI-module component for Elliptics file storage
// Copyright (C) 2011 Leonid A. Movsesjan <lmovsesjan@yandex-team.ru>

// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

#ifndef _EMBED_PROCESSOR_HPP_INCLUDED_
#define _EMBED_PROCESSOR_HPP_INCLUDED_

#include <boost/shared_ptr.hpp>

#include <fastcgi2/component.h>
#include <fastcgi2/handler.h>
#include <fastcgi2/logger.h>
#include <fastcgi2/request.h>

#include <elliptics/cppdef.h>

namespace elliptics {

enum dnet_common_embed_types {
	DNET_FCGI_EMBED_DATA	    = 1,
	DNET_FCGI_EMBED_TIMESTAMP,
};

struct dnet_common_embed {
	uint64_t		size;
	uint32_t		type;
	uint32_t		flags;
	uint8_t		 data[0];
};

static inline void
dnet_common_convert_embedded(struct dnet_common_embed *e) {
	e->size = dnet_bswap64(e->size);
	e->type = dnet_bswap32(e->type);
	e->flags = dnet_bswap32(e->flags);
}


class EmbedProcessorModuleBase : virtual public fastcgi::Component{

public:
	EmbedProcessorModuleBase(fastcgi::ComponentContext *context);
	virtual ~EmbedProcessorModuleBase();

public:
	virtual void onLoad();
	virtual void onUnload();

public:
	virtual bool processEmbed(fastcgi::Request *request, struct dnet_common_embed &embed, int &http_status);

protected:
	fastcgi::Logger* log() const {
		return logger_;
	}
	fastcgi::Logger *logger_;

};

} // namespace elliptics

#endif // _EMBED_PROCESSOR_HPP_INCLUDED_

