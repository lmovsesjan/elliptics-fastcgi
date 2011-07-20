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

#ifndef _ELLIPTICS_FASTCGI_HPP_INCLUDED_
#define _ELLIPTICS_FASTCGI_HPP_INCLUDED_

#include <map>
#include <set>
#include <string>

#include <fastcgi2/component.h>
#include <fastcgi2/handler.h>
#include <fastcgi2/logger.h>
#include <fastcgi2/request.h>

#ifdef HAVE_GEOBASE
#include <geobase3/lookup.hpp>
#include <fastcgi-elliptics/regional_module.hpp>
#endif

#include <boost/tokenizer.hpp>

#include <elliptics/cppdef.h>

#include "boost_threaded.hpp"
#include "refresher.hpp"

namespace elliptics {

class EllipticsProxy;

typedef void (EllipticsProxy::*RequestHandler)(fastcgi::Request *request);

class EllipticsProxy : virtual public fastcgi::Component, virtual public fastcgi::Handler {

private:
	typedef std::map<std::string, RequestHandler> RequestHandlers;
	typedef boost::char_separator<char> Separator;
	typedef boost::tokenizer<Separator> Tokenizer;

public:
	EllipticsProxy(fastcgi::ComponentContext *context);
	virtual ~EllipticsProxy();

private:
	void registerHandler(const char *name, RequestHandler handler);

	void pingHandler(fastcgi::Request *request);
	void downloadInfoHandler(fastcgi::Request *request);
	void getHandler(fastcgi::Request *request);
	void statLogHandler(fastcgi::Request *request);
	void uploadHandler(fastcgi::Request *request);
	void deleteHandler(fastcgi::Request *request);

	fastcgi::Logger* log() const {
		return logger_;
	}

	void allowOrigin(fastcgi::Request *request) const;

	std::vector<int> getGroups(fastcgi::Request *request) const;
	void uploadMetaInfo(const std::vector<int> &groups, const std::string &filename) const;
	std::vector<int> getMetaInfo(const std::string &filename) const;

#ifdef HAVE_GEOBASE
	void refresh();
#endif

	static size_t paramsNum(Tokenizer &tok);
	static std::string md5(const std::string &source);

	std::pair<std::string, time_t> secret(fastcgi::Request *request) const;

public:
	virtual void onLoad();
	virtual void onUnload();
	virtual void handleRequest(fastcgi::Request *request, fastcgi::HandlerContext *context);

private:
	fastcgi::Logger                            *logger_;
	RequestHandlers                             handlers_;
#ifdef HAVE_GEOBASE
	boost::shared_ptr<geobase3::lookup>         lookup_;
	std::auto_ptr<Refresher>                    refresher_;
	boost::mutex                                mutex_;
	std::string                                 filename_;
	time_t                                      last_modified_;
	RegionalModule*                             regional_module_;
#endif
	boost::shared_ptr<elliptics_log_file>       elliptics_log_;
	boost::shared_ptr<elliptics_node>           elliptics_node_;
	std::map<std::string, std::string>          typemap_;
	std::vector<std::string>                    remotes_;
	std::vector<int>                            groups_;
	std::size_t                                 success_copies_num_;
	int                                         state_num_;
	int                                         base_port_;
	int                                         write_port_;
	int                                         directory_bit_num_;
	bool                                        use_cookie_;
	std::string                                 sign_key_;
	std::string                                 cookie_name_;
	std::string                                 cookie_key_;
	std::string                                 cookie_path_;
	std::string                                 cookie_domain_;
	time_t                                      cookie_expires_;
	std::set<std::string>                       deny_list_;
	std::set<std::string>                       allow_list_;
	time_t                                      expires_;
	std::string                                 metabase_write_addr_;
	std::string                                 metabase_read_addr_;
	std::string                                 allow_origin_domain_;
	std::set<std::string>                       allow_origin_handlers_;

};

} // namespace elliptics

#endif // _ELLIPTICS_FASTCGI_HPP_INCLUDED_

