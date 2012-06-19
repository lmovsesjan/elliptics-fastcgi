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

#include "settings.h"

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
#endif /* HAVE_GEOBASE */

#ifdef HAVE_METABASE
#include <zmq.hpp>
#include <msgpack.hpp>
#endif /* HAVE_METABASE */

#include <boost/tokenizer.hpp>

#include <elliptics/cppdef.h>

#include "boost_threaded.hpp"
#include "refresher.hpp"
#include "embed_processor.hpp"

namespace elliptics {

#ifdef HAVE_METABASE
struct MetabaseRequest {
	int		groups_num;
	uint64_t	stamp;
	std::vector<uint8_t> id;
	MSGPACK_DEFINE(groups_num, stamp, id);
};

struct MetabaseResponse {
	std::vector<int> groups;
	uint64_t	stamp;
	MSGPACK_DEFINE(groups, stamp);
};
#endif /* HAVE_METABASE */

class EllipticsProxy;

typedef void (EllipticsProxy::*RequestHandler)(fastcgi::Request *request);

class EllipticsProxy : virtual public fastcgi::Component, virtual public fastcgi::Handler {
	class cookie_sign {
	public:
		std::string                                 sign_key;
		std::string                                 path;
	};

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
	void rangeHandler(fastcgi::Request *request);
	void rangeDeleteHandler(fastcgi::Request *request);
	void statLogHandler(fastcgi::Request *request);
	void uploadHandler(fastcgi::Request *request);
	void deleteHandler(fastcgi::Request *request);
	void bulkReadHandler(fastcgi::Request *request);
	void bulkWriteHandler(fastcgi::Request *request);
	void execScriptHandler(fastcgi::Request *request);

	void dnet_parse_numeric_id(const std::string &value, struct dnet_id &id);

	fastcgi::Logger* log() const {
		return logger_;
	}

	void allowOrigin(fastcgi::Request *request) const;

	std::vector<int> getGroups(fastcgi::Request *request, size_t count = 0) const;
	void uploadMetaInfo(const std::vector<int> &groups, const std::string &filename) const;
	std::vector<int> getMetaInfo(const std::string &filename) const;

#ifdef HAVE_GEOBASE
	void refresh();
#endif /* HAVE_GEOBASE */

	static size_t paramsNum(Tokenizer &tok);
	static std::string md5(const std::string &source);

	std::pair<std::string, time_t> secret(fastcgi::Request *request) const;

#ifdef HAVE_METABASE
	std::vector<int> getMetabaseGroups(fastcgi::Request *request, size_t count, struct dnet_id &id);
#endif /* HAVE_METABASE */

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
#endif /* HAVE_GEOBASE */
#ifdef HAVE_METABASE
	std::auto_ptr<zmq::context_t>               metabase_context_;
	std::auto_ptr<zmq::socket_t>                metabase_socket_;
	int                                         metabase_timeout_;
	int                                         metabase_usage_;
	uint64_t                                    metabase_current_stamp_;
#endif /* HAVE_METABASE */
	boost::shared_ptr<ioremap::elliptics::log_file>  elliptics_log_;
	boost::shared_ptr<ioremap::elliptics::node>      elliptics_node_;
	std::map<std::string, std::string>          typemap_;
	std::vector<std::string>                    remotes_;
	std::vector<int>                            groups_;
	int                                         success_copies_num_;
	int                                         state_num_;
	int                                         replication_count_;
	int                                         base_port_;
	int                                         write_port_;
	int                                         directory_bit_num_;
	int                                         eblob_style_path_;
	int                                         chunk_size_;
	bool                                        use_cookie_;
	std::string                                 cookie_name_;
	std::string                                 cookie_key_;
	std::string                                 cookie_path_;
	std::string                                 cookie_domain_;
	time_t                                      cookie_expires_;
	std::vector<EllipticsProxy::cookie_sign>    cookie_signs_;
	std::set<std::string>                       deny_list_;
	std::set<std::string>                       allow_list_;
	time_t                                      expires_;
	std::string                                 metabase_write_addr_;
	std::string                                 metabase_read_addr_;
	std::set<std::string>                       allow_origin_domains_;
	std::set<std::string>                       allow_origin_handlers_;
        std::vector<std::pair<uint32_t, EmbedProcessorModuleBase*> > embed_processors_;

};

} // namespace elliptics

#endif // _ELLIPTICS_FASTCGI_HPP_INCLUDED_

