// embed_processor - FastCGI-module component for Elliptics file storage
// Copyright (C) 2012 Anton Kortunov <toshik@yandex-team.ru>

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

#include "settings.h"

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#include <fcntl.h>
#include <errno.h>
#include <netdb.h>

#include <fstream>

#include <boost/bind.hpp>

#include <fastcgi2/config.h>
#include <fastcgi2/component_factory.h>
#include <fastcgi2/cookie.h>
#include <fastcgi2/except.h>
#include <fastcgi2/util.h>

#include "embed_processor.hpp"


namespace elliptics {

EmbedProcessorModuleBase::EmbedProcessorModuleBase(fastcgi::ComponentContext *context) :
	fastcgi::Component(context),
	logger_(NULL) {
}

EmbedProcessorModuleBase::~EmbedProcessorModuleBase() {
}

void
EmbedProcessorModuleBase::onLoad() {
	assert(NULL == logger_);

	const fastcgi::Config *config = context()->getConfig();
	std::string path(context()->getComponentXPath());

	logger_ = context()->findComponent<fastcgi::Logger>(config->asString(path + "/logger"));
	if (!logger_) {
		throw std::logic_error("can't find logger");
	}
}

void
EmbedProcessorModuleBase::onUnload() {
}

bool EmbedProcessorModuleBase::processEmbed(fastcgi::Request *request, struct dnet_common_embed &embed, int &http_status) {
    http_status = 200;
    return true;
}

}

