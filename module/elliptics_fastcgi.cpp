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

#include "settings.h"

#include <sstream>

#include <fcntl.h>
#include <errno.h>
#include <netdb.h>

#include <sys/socket.h>

#include <openssl/md5.h>

#include <fastcgi2/config.h>
#include <fastcgi2/component_factory.h>
#include <fastcgi2/cookie.h>
#include <fastcgi2/except.h>
#include <fastcgi2/util.h>

#include <boost/bind.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/tokenizer.hpp>
#include <boost/scoped_array.hpp>

#include <eblob/blob.h>

#include "curl_wrapper.hpp"
#include "elliptics_fastcgi.hpp"

namespace elliptics {

enum dnet_metabase_type {
	DNET_FCGI_META_NONE = 0,
	DNET_FCGI_META_OPTIONAL,
	DNET_FCGI_META_NORMAL,
	DNET_FCGI_META_MANDATORY,
};

static inline char*
file_backend_get_dir(const unsigned char *id, uint64_t bit_num, char *dst) {
	char *res = dnet_dump_id_len_raw(id, ALIGN(bit_num, 8) / 8, dst);

	if (res) {
		res[bit_num / 4] = '\0';
	}

	return res;
}

static int
dnet_common_prepend_data(struct timespec *ts, uint64_t size, char *buf, int *bufsize) {
	char *orig = buf;
	struct dnet_common_embed *e = (struct dnet_common_embed*)buf;
	uint64_t *edata = (uint64_t *)e->data;

	if (*bufsize < (int)(sizeof (struct dnet_common_embed) + sizeof (uint64_t)) * 2) {
		return -ENOBUFS;
	}

	e->size = sizeof (uint64_t) * 2;
	e->type = DNET_FCGI_EMBED_TIMESTAMP;
	e->flags = 0;
	dnet_common_convert_embedded(e);

	edata[0] = dnet_bswap64(ts->tv_sec);
	edata[1] = dnet_bswap64(ts->tv_nsec);

	buf += sizeof (struct dnet_common_embed) + sizeof (uint64_t) * 2;

	e = (struct dnet_common_embed*)buf;
	e->size = size;
	e->type = DNET_FCGI_EMBED_DATA;
	e->flags = 0;
	dnet_common_convert_embedded(e);

	buf += sizeof (struct dnet_common_embed);

	*bufsize = buf - orig;
	return 0;
}

EllipticsProxy::EllipticsProxy(fastcgi::ComponentContext *context) :
	fastcgi::Component(context),
	logger_(NULL)
#ifdef HAVE_REGIONAL
	, regional_module_(NULL)
#endif /* HAVE_REGIONAL */
{
}

EllipticsProxy::~EllipticsProxy() {
}

std::pair<std::string, time_t>
EllipticsProxy::secret(fastcgi::Request *request) const {
	if (request->hasCookie(cookie_name_)) {
		std::string cookie = request->getCookie(cookie_name_);

		Separator sep(".");
		Tokenizer tok(cookie, sep);

		if (paramsNum(tok) == 2) {
			return std::make_pair(request->getCookie(cookie_name_), time(NULL));
		}
	}

	boost::uint32_t rnd;

	int urandom = open("/dev/urandom", O_RDONLY);
	if (urandom < 0) {
		std::ostringstream ostr;
		ostr << "can not generate random bytes with errno " << -errno;
		throw std::runtime_error(ostr.str());
	}

	int err = read(urandom, &rnd, sizeof (rnd));

	close(urandom);
	if (err < 0) {
		err = -errno;

		std::ostringstream ostr;
		ostr << "can not generate random bytes with errno " << err;
		throw std::runtime_error(ostr.str());
	}

	time_t timestamp = time(NULL);
	std::ostringstream ostr;
	ostr << cookie_key_ << std::hex << rnd << std::hex << timestamp;

	char cookie[256];
	snprintf(cookie, sizeof (cookie), "%x.%lx.%s", rnd, timestamp, md5(ostr.str()).c_str());

	fastcgi::Cookie c(cookie_name_, cookie);
	c.expires(timestamp + cookie_expires_);
	c.path(cookie_path_);
	c.domain(cookie_domain_);

	request->setCookie(c);

	return std::make_pair(cookie, timestamp);
}

std::string
EllipticsProxy::md5(const std::string &source) {
	MD5_CTX md5handler;
	unsigned char md5buffer[16];

	MD5_Init(&md5handler);
	MD5_Update(&md5handler, (unsigned char *)source.c_str(), source.length());
	MD5_Final(md5buffer, &md5handler);

	char alpha[16] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};
	unsigned char c;
	std::string md5digest;
	md5digest.reserve(32);

	for (int i = 0; i < 16; ++i) {
		c = (md5buffer[i] & 0xf0) >> 4;
		md5digest.push_back(alpha[c]);
		c = (md5buffer[i] & 0xf);
		md5digest.push_back(alpha[c]);
	}

	return md5digest;
}

void
EllipticsProxy::handleRequest(fastcgi::Request *request, fastcgi::HandlerContext *context) {
	(void)context;
	try {
		std::string handler;
		if (request->getQueryString().length() != 0) {
			if (request->hasArg("stat") || request->hasArg("ping")) {
				handler = "stat";
			}
			else if (request->hasArg("stat_log")) {
				handler = "stat-log";
			}
			else if (request->hasArg("direct")) {
				handler = "get";
			}
			else if (request->hasArg("range")) {
				handler = "range";
			}
			else if (request->hasArg("range-delete")) {
				handler = "range-delete";
			}
			else if (request->hasArg("unlink")) {
				handler = "delete";
			}
			else if (request->hasArg("bulk-read")) {
				handler = "bulk-read";
			}
			else if (request->hasArg("bulk-write")) {
				handler = "bulk-write";
			}
			else if (request->hasArg("exec-script")) {
				handler = "exec-script";
			}
			else {
				if (request->hasArg("name")) {
					handler = request->getServerPort() == write_port_ ? "upload" : "download-info";
				}
				else {
					handler = request->getScriptName().substr(1, std::string::npos);
				}
			}
		}
		else {
			handler = request->getScriptName().substr(1, std::string::npos);
		}
		std::string::size_type pos = handler.find('/');
		handler = handler.substr(0, pos);
		RequestHandlers::iterator it = handlers_.find(handler);
		if (handlers_.end() == it) {
			throw fastcgi::HttpException(404);
		}

		if (allow_origin_handlers_.end() != allow_origin_handlers_.find(handler)) {
			allowOrigin(request);
		}

		(this->*it->second)(request);
	}
	catch (const fastcgi::HttpException &e) {
		throw;
	}
	catch (...) {
		throw fastcgi::HttpException(501);
	}
}

void
EllipticsProxy::allowOrigin(fastcgi::Request *request) const {
	if (0 == allow_origin_domains_.size()) {
		return;
	}

	if (!request->hasHeader("Origin")) {
		return;
	}

	std::string domain = request->getHeader("Origin");
	if (!domain.compare(0, sizeof ("http://") - 1, "http://")) {
		domain = domain.substr(sizeof ("http://") - 1, std::string::npos);
	}

	for (std::set<std::string>::const_iterator it = allow_origin_domains_.begin(), end = allow_origin_domains_.end();
		end != it; ++it) {
		std::string allow_origin_domain = *it;

		if (domain.length() < allow_origin_domain.length() - 1) {
			continue;
		}

		bool allow = false;

		if (domain.length() == allow_origin_domain.length() - 1) {
			allow = !allow_origin_domain.compare(1, std::string::npos, domain);
		}
		else {
			allow = !domain.compare(domain.length() - allow_origin_domain.length(), std::string::npos, allow_origin_domain);
		}

		if (allow) {
			domain = (!request->getHeader("Origin").compare(0, sizeof ("https://") - 1, "https://") ? "https://" : "http://") + domain;
			request->setHeader("Access-Control-Allow-Origin", domain);
			request->setHeader("Access-Control-Allow-Credentials", "true");
			return;
		}
	}
	throw fastcgi::HttpException(403);
}

void
EllipticsProxy::registerHandler(const char *name, RequestHandler handler) {
	RequestHandlers::iterator it = handlers_.find(name);
	if (handlers_.end() != it) {
		log()->error("repeated registration of %s handler", name);
		return;
	}
	handlers_.insert(std::make_pair(name, handler));
}

void
EllipticsProxy::onLoad() {
	assert(NULL == logger_);

	std::vector<std::string> names;

	const fastcgi::Config *config = context()->getConfig();
	std::string path(context()->getComponentXPath());

	logger_ = context()->findComponent<fastcgi::Logger>(config->asString(path + "/logger"));
	if (!logger_) {
		throw std::logic_error("can't find logger");
	}

#ifdef HAVE_REGIONAL
	regional_module_ = context()->findComponent<RegionalModule>(config->asString(path + "/regional-module", "regional-module"));
#endif /* HAVE_REGIONAL */

	state_num_ = config->asInt(path + "/dnet/die-limit");
	base_port_ = config->asInt(path + "/dnet/base-port");
	write_port_ = config->asInt(path + "/dnet/write-port", 9000);
	directory_bit_num_ = config->asInt(path + "/dnet/directory-bit-num");
        eblob_style_path_ = config->asInt(path + "/dnet/eblob_style_path", 0);

	replication_count_ = config->asInt(path + "/dnet/replication-count", 0);
	chunk_size_ = config->asInt(path + "/dnet/chunk_size", 0);
	if (chunk_size_ < 0) chunk_size_ = 0;

	use_cookie_ = (config->asString(path + "/dnet/cookie/name", "") != "");

	if (use_cookie_) {
		cookie_name_ = config->asString(path + "/dnet/cookie/name");
		cookie_key_ = config->asString(path + "/dnet/cookie/key");
		cookie_path_ = config->asString(path + "/dnet/cookie/path");
		cookie_domain_ = config->asString(path + "/dnet/cookie/domain");
		cookie_expires_ = config->asInt(path + "/dnet/cookie/expires");

		names.clear();
		config->subKeys(path + "/dnet/cookie/sign", names);
		for (std::vector<std::string>::iterator it = names.begin(), end = names.end(); end != it; ++it) {
			EllipticsProxy::cookie_sign cookie_;

			cookie_.path = config->asString(*it + "/path");
			cookie_.sign_key = config->asString(*it + "/sign_key");

			log()->debug("cookie %s path %s", it->c_str(), cookie_.path.c_str());
			cookie_signs_.push_back(cookie_);
		}
	}
	
	std::string elliptics_log_filename = config->asString(path + "/dnet/log/path");
	uint32_t elliptics_log_mask = config->asInt(path + "/dnet/log/mask");
	elliptics_log_.reset(new ioremap::elliptics::log_file(elliptics_log_filename.c_str(), elliptics_log_mask));

	struct dnet_config dnet_conf;
	memset(&dnet_conf, 0, sizeof (dnet_conf));

	dnet_conf.wait_timeout = config->asInt(path + "/dnet/wait-timeout", 0);
	dnet_conf.check_timeout = config->asInt(path + "/dnet/reconnect-timeout", 0);
	dnet_conf.flags = config->asInt(path + "/dnet/cfg-flags", 4);

	elliptics_node_.reset(new ioremap::elliptics::node(*elliptics_log_, dnet_conf));

	names.clear();
	config->subKeys(path + "/dnet/remote/addr", names);

	for (std::vector<std::string>::iterator it = names.begin(), end = names.end(); end != it; ++it) {
		std::string remote = config->asString(it->c_str());
		Separator sep(":");
		Tokenizer tok(remote, sep);

		if (paramsNum(tok) != 2) {
			log()->error("invalid dnet remote %s", remote.c_str());
			continue;
		}

		std::string addr;
		int port, family;

		try {
			Tokenizer::iterator tit = tok.begin();
			addr = *tit;
			port = boost::lexical_cast<int>(*(++tit));
			family = boost::lexical_cast<int>(*(++tit));
		}
		catch (...) {
			log()->error("invalid dnet remote %s", remote.c_str());
			continue;
		}

		try {
			remotes_.push_back(remote);
			elliptics_node_->add_remote(addr.c_str(), port, family);
			log()->info("added dnet remote %s:%d:%d", addr.c_str(), port, family);
		}
		catch (const std::exception &e) {
			log()->error("invalid dnet remote %s %s", remote.c_str(), e.what());
		}
		catch (...) {
			log()->error("invalid dnet remote %s", remote.c_str());
		}
	}

	names.clear();
	config->subKeys(path + "/dnet/allow/extention", names);
	for (std::vector<std::string>::iterator it = names.begin(), end = names.end(); end != it; ++it) {
		allow_list_.insert(config->asString(it->c_str()));
	}

	names.clear();
	config->subKeys(path + "/dnet/deny/extention", names);
	for (std::vector<std::string>::iterator it = names.begin(), end = names.end(); end != it; ++it) {
		deny_list_.insert(config->asString(it->c_str()));
	}

	std::string groups = config->asString(path + "/dnet/groups", "");

	Separator sep(":");
	Tokenizer tok(groups, sep);

	for (Tokenizer::iterator it = tok.begin(), end = tok.end(); end != it; ++it) {
		try {
			groups_.push_back(boost::lexical_cast<int>(*it));
		}
		catch (...) {
			log()->error("invalid dnet group id %s", it->c_str());
		}
	}

/*
	if (groups_.size() != 0) {
		try {
			elliptics_node_->add_groups(groups_);
			log()->info("added dnet groups %s", groups.c_str());
		}
		catch (const std::exception &e) {
			log()->error("can not add dnet groups %s %s", groups.c_str(), e.what());
		}
		catch (...) {
			log()->error("can not add dnet groups %s", groups.c_str());
		}
	}
*/
	success_copies_num_ = config->asInt(path + "/dnet/success-copies-num", groups_.size());

	std::vector<std::string> typemap;
	config->subKeys(path + "/dnet/typemap/type", typemap);

	for (std::vector<std::string>::iterator it = typemap.begin(), end = typemap.end(); end != it; ++it) {
		std::string match = config->asString(it->c_str());

		std::string::size_type pos = match.find("->");
		std::string extention = match.substr(0, pos);
		std::string type = match.substr(pos + sizeof ("->") - 1, std::string::npos);

		typemap_[extention] = type;
	}

	expires_ = config->asInt(path + "/dnet/expires-time", 0);

	metabase_write_addr_ = config->asString(path + "/dnet/metabase/write-addr", "");
	metabase_read_addr_ = config->asString(path + "/dnet/metabase/read-addr", "");
#ifdef HAVE_METABASE
	metabase_current_stamp_ = 0;
	metabase_usage_ = DNET_FCGI_META_NONE;
	names.clear();
	config->subKeys(path + "/metabase/addr", names);
	if (names.size() > 0) {
		try {
			metabase_context_.reset(new zmq::context_t(config->asInt(path + "/metabase/net_threads", 1)));
			metabase_socket_.reset(new zmq::socket_t(*metabase_context_, ZMQ_DEALER));

			// Disable linger so that the socket won't hang for eternity waiting for the peer
			int linger = 0;
			metabase_socket_->setsockopt(ZMQ_LINGER, &linger, sizeof(linger));

			for (std::vector<std::string>::iterator it = names.begin(), end = names.end(); end != it; ++it) {
				log()->debug("connecting to zmq host %s", config->asString(it->c_str()).c_str());
				metabase_socket_->connect(config->asString(it->c_str()).c_str());
			}

			// Default timeout is 100ms
			metabase_timeout_ = config->asInt(path + "/metabase/timeout", 100 * 1000);

			std::string cfg_metabase_usage = config->asString(path + "/metabase/usage", "normal");
			if (!cfg_metabase_usage.compare("normal")) {
				metabase_usage_ = DNET_FCGI_META_NORMAL;
			} else if (!cfg_metabase_usage.compare("optional")) {
				metabase_usage_ = DNET_FCGI_META_OPTIONAL;
			} else if (!cfg_metabase_usage.compare("mandatory")) {
				metabase_usage_ = DNET_FCGI_META_MANDATORY;
			} else {
				throw std::runtime_error(std::string("Incorrect metabase usage type: ") + cfg_metabase_usage);
			}
			log()->debug("cfg_metabase_usage %s, metabase_usage_ %d", cfg_metabase_usage.c_str(), metabase_usage_);

		}
		catch (const std::exception &e) {
			log()->error("can not connect to metabase: %s", e.what());
			metabase_socket_.release();
		}
		catch (...) {
			log()->error("can not connect to metabase");
			metabase_socket_.release();
		}
	}

#endif /* HAVE_METABASE */

	names.clear();
	config->subKeys(path + "/embed_processors/processor", names);
	for (std::vector<std::string>::iterator it = names.begin(), end = names.end(); end != it; ++it) {
		EmbedProcessorModuleBase *processor = context()->findComponent<EmbedProcessorModuleBase>(config->asString(*it + "/name"));
		if (!processor) {
			log()->error("Embed processor %s doesn't exists in config", config->asString(*it + "/name").c_str());
		} else {
	                embed_processors_.push_back(std::make_pair(config->asInt(*it + "/type"), processor));
		}
	}

	names.clear();
	config->subKeys(path + "/dnet/allow-origin/domains/domain", names);
	for (std::vector<std::string>::iterator it = names.begin(), end = names.end(); end != it; ++it) {
		allow_origin_domains_.insert(config->asString(it->c_str()));
	}

	names.clear();
	config->subKeys(path + "/dnet/allow-origin/handlers/handler", names);
	for (std::vector<std::string>::iterator it = names.begin(), end = names.end(); end != it; ++it) {
		allow_origin_handlers_.insert(config->asString(it->c_str()));
	}

	registerHandler("ping", &EllipticsProxy::pingHandler);
	registerHandler("download-info", &EllipticsProxy::downloadInfoHandler);
	registerHandler("get", &EllipticsProxy::getHandler);
	registerHandler("range", &EllipticsProxy::rangeHandler);
	registerHandler("range-delete", &EllipticsProxy::rangeDeleteHandler);
	registerHandler("stat", &EllipticsProxy::pingHandler);
	registerHandler("stat_log", &EllipticsProxy::statLogHandler);
	registerHandler("stat-log", &EllipticsProxy::statLogHandler);
	registerHandler("upload", &EllipticsProxy::uploadHandler);
	registerHandler("delete", &EllipticsProxy::deleteHandler);
	registerHandler("bulk-read", &EllipticsProxy::bulkReadHandler);
	registerHandler("bulk-write", &EllipticsProxy::bulkWriteHandler);
	registerHandler("exec-script", &EllipticsProxy::execScriptHandler);
}

void
EllipticsProxy::onUnload() {
}

void
EllipticsProxy::pingHandler(fastcgi::Request *request) {
	ioremap::elliptics::session sess(*elliptics_node_);
	if (sess.state_num() < state_num_) {
		request->setStatus(500);
	}
	else {
		request->setStatus(200);
	}
}

void
EllipticsProxy::downloadInfoHandler(fastcgi::Request *request) {
	std::string filename = request->hasArg("name") ? request->getArg("name") :
		request->getScriptName().substr(sizeof ("/download-info/") - 1, std::string::npos);

	ioremap::elliptics::session sess(*elliptics_node_);
	std::vector<int> groups;
        std::string path;
	if (!metabase_write_addr_.empty() && !metabase_read_addr_.empty()) {
		try {
			groups = getMetaInfo(filename);
		}
		catch (...) {
			groups = getGroups(request);
		}
	}
	else {
		groups = getGroups(request);
	}

	try {
		sess.add_groups(groups);
		std::string l = sess.lookup(filename);

		std::string result = "<?xml version=\"1.0\" encoding=\"utf-8\"?>";

		const void *data = l.data();

		struct dnet_addr *addr = (struct dnet_addr *)data;
		struct dnet_cmd *cmd = (struct dnet_cmd *)(addr + 1);
		struct dnet_addr_attr *a = (struct dnet_addr_attr *)(cmd + 1);
		struct dnet_file_info *info = (struct dnet_file_info *)(a + 1);
		dnet_convert_file_info(info);

		char hbuf[NI_MAXHOST];
		memset(hbuf, 0, NI_MAXHOST);

		if (getnameinfo((const sockaddr*)&a->addr, a->addr.addr_len, hbuf, sizeof (hbuf), NULL, 0, 0) != 0) {
			throw std::runtime_error("can not make dns lookup");
		}

		int port = dnet_server_convert_port((struct sockaddr *)a->addr.addr, a->addr.addr_len);

		char id[2 * DNET_ID_SIZE + 1];
		char hex_dir[2 * DNET_ID_SIZE + 1];

		struct dnet_id eid;
		sess.transform(filename, eid);

		dnet_dump_id_len_raw(eid.id, DNET_ID_SIZE, id);
		file_backend_get_dir(eid.id, directory_bit_num_, hex_dir);

		sess.add_groups(groups_);

		std::string region = "-1";
		std::string ip = request->hasHeader("X-Real-IP") ? request->getHeader("X-Real-IP") : request->getRemoteAddr();

		result += "<download-info>";

#ifdef HAVE_REGIONAL
		if (NULL != regional_module_) {
			region = regional_module_->getRegion(ip);
			std::vector<std::string> hosts = regional_module_->getHosts(ip);
			if (hosts.size() != 0) {
				char f_str[2];
				strncpy(f_str, id + sizeof (id) - 3, sizeof (f_str));
				unsigned int f;
				sscanf(f_str, "%x", &f);
				size_t n = f % hosts.size();
				std::swap(hosts[n], hosts[0]);

				for (std::size_t i = 0; i < std::min(hosts.size(), (size_t)2); ++i) {
					std::string index = boost::lexical_cast<std::string>(i);
					std::string host = std::string(hbuf) + '.' + hosts[i];

					try {
						std::stringstream tmp;

						std::string url = host + "/ping";
						yandex::common::curl_wrapper<yandex::common::boost_threading_traits> curl(url);
						curl.header("Expect", "");
						curl.timeout(1);
						long status = curl.perform(tmp);

						if (200 != status) {
							throw std::runtime_error("non 200 status from regional proxy");
						}

						result += "<regional-host>" + host + "</regional-host>";
					}
					catch (...) {
					}
				}
			}
		}
#endif /* HAVE_REGIONAL */


		if (eblob_style_path_) {
			path = std::string((char *)(info + 1));
			path = path.substr(path.find_last_of("/\\") + 1);
			path = "/" + boost::lexical_cast<std::string>(port - base_port_) + '/' 
				+ path + ":" + boost::lexical_cast<std::string>(info->offset)
				+ ":" +  boost::lexical_cast<std::string>(info->size);
		} else {
			path = "/" + boost::lexical_cast<std::string>(port - base_port_) + '/' + hex_dir + '/' + id;
		}

		EllipticsProxy::cookie_sign cookie;
		std::string full_path = "/" + filename;
		for (std::vector<EllipticsProxy::cookie_sign>::iterator it = cookie_signs_.begin(); it != cookie_signs_.end(); it++) {

			if (full_path.size() < it->path.size())
				continue;

			if (full_path.compare(0, it->path.size(), it->path, 0, it->path.size()))
				continue;

			cookie = *it;
			break;
		}

		std::pair<std::string, time_t> s = cookie.sign_key.size() ? secret(request) : std::make_pair(std::string(), time(NULL));

		std::ostringstream ostr;
		ostr << cookie.sign_key << std::hex << s.second << s.first << path;
		log()->debug("sign_source %s", ostr.str().c_str());
		std::string sign = md5(ostr.str());

		char tsstr[32];
		snprintf(tsstr, sizeof (tsstr), "%lx", s.second);

		result += "<host>" + std::string(hbuf) + "</host><path>" + path + "</path>" + "<ts>" + tsstr + "</ts>";
		result += "<region>" + region + "</region>";
		result += "<s>" + sign + "</s></download-info>";

		request->setStatus(200);
		request->setContentType("text/xml");
		request->write(result.c_str(), result.length());
	}
	catch (const std::exception &e) {
		log()->error("can not get download info for file %s %s", filename.c_str(), e.what());
		request->setStatus(404);
	}
	catch (...) {
		log()->error("can not get download info for file %s", filename.c_str());
		request->setStatus(404);
	}
}

void
EllipticsProxy::rangeHandler(fastcgi::Request *request) {
	std::string filename = request->hasArg("name") ? request->getArg("name") :
		request->getScriptName().substr(sizeof ("/range/") - 1, std::string::npos);

	ioremap::elliptics::session sess(*elliptics_node_);
	std::vector<int> groups;
	if (!metabase_write_addr_.empty() && !metabase_read_addr_.empty()) {
		try {
			groups = getMetaInfo(filename);
		}
		catch (...) {
			groups = getGroups(request);
		}
	}
	else {
		groups = getGroups(request);
	}

	std::string extention = filename.substr(filename.rfind('.') + 1, std::string::npos);

	if (deny_list_.find(extention) != deny_list_.end() ||
		(deny_list_.find("*") != deny_list_.end() &&
		allow_list_.find(extention) == allow_list_.end())) {
		throw fastcgi::HttpException(403);
	}

	std::map<std::string, std::string>::iterator it = typemap_.find(extention);

	std::string content_type = "application/octet";

	try {
		unsigned int aflags = request->hasArg("aflags") ? boost::lexical_cast<unsigned int>(request->getArg("aflags")) : 0;
		unsigned int ioflags = request->hasArg("ioflags") ? boost::lexical_cast<unsigned int>(request->getArg("ioflags")) : 0;
		int column = request->hasArg("column") ? boost::lexical_cast<int>(request->getArg("column")) : 0;

		if (request->hasArg("count_only"))
			ioflags |= DNET_IO_FLAGS_NODATA;

		struct dnet_io_attr io;
		memset(&io, 0, sizeof(struct dnet_io_attr));

		struct dnet_id tmp;

		if (request->hasArg("from")) {
			dnet_parse_numeric_id(request->getArg("from"), tmp);
			memcpy(io.id, tmp.id, sizeof(io.id));
		}

		if (request->hasArg("to")) {
			dnet_parse_numeric_id(request->getArg("to"), tmp);
			memcpy(io.parent, tmp.id, sizeof(io.parent));
		} else {
			memset(io.parent, 0xff, sizeof(io.parent));
		}

		if (request->hasArg("limit_start")) {
			io.start = boost::lexical_cast<uint64_t>(request->getArg("limit_start"));
		}
		if (request->hasArg("limit_num")) {
			io.num = boost::lexical_cast<uint64_t>(request->getArg("limit_num"));
		}

		io.flags = ioflags;
		io.type = column;

		std::vector<std::string> ret;

		for (size_t i = 0; i < groups.size(); ++i) {
			try {
				ret = sess.read_data_range(io, groups[i], aflags);
				if (ret.size())
					break;
			} catch (...) {
				continue;
			}
		}

		if (ret.size() == 0) {
			std::ostringstream str;
			str << filename.c_str() << ": READ_RANGE failed in " << groups.size() << " groups";
			throw std::runtime_error(str.str());
		}

		std::string result;

		for (size_t i = 0; i < ret.size(); ++i) {
			result += ret[i];
		}

		request->setStatus(200);
		request->setContentType(content_type);
		request->setHeader("Content-Length", boost::lexical_cast<std::string>(result.length()));
		request->write(result.data(), result.size());
	}
	catch (const std::exception &e) {
		log()->error("%s: READ_RANGE failed: %s", filename.c_str(), e.what());
		request->setStatus(404);
	}
	catch (...) {
		log()->error("%s: READ_RANGE failed", filename.c_str());
		request->setStatus(404);
	}
}

void
EllipticsProxy::rangeDeleteHandler(fastcgi::Request *request) {
	std::string filename = request->hasArg("name") ? request->getArg("name") :
		request->getScriptName().substr(sizeof ("/range/") - 1, std::string::npos);

	ioremap::elliptics::session sess(*elliptics_node_);
	std::vector<int> groups;
	if (!metabase_write_addr_.empty() && !metabase_read_addr_.empty()) {
		try {
			groups = getMetaInfo(filename);
		}
		catch (...) {
			groups = getGroups(request);
		}
	}
	else {
		groups = getGroups(request);
	}

	std::string extention = filename.substr(filename.rfind('.') + 1, std::string::npos);

	if (deny_list_.find(extention) != deny_list_.end() ||
		(deny_list_.find("*") != deny_list_.end() &&
		allow_list_.find(extention) == allow_list_.end())) {
		throw fastcgi::HttpException(403);
	}

	std::map<std::string, std::string>::iterator it = typemap_.find(extention);

	std::string content_type = "application/octet";

	try {
		unsigned int aflags = request->hasArg("aflags") ? boost::lexical_cast<unsigned int>(request->getArg("aflags")) : 0;
		unsigned int ioflags = request->hasArg("ioflags") ? boost::lexical_cast<unsigned int>(request->getArg("ioflags")) : 0;
		int column = request->hasArg("column") ? boost::lexical_cast<int>(request->getArg("column")) : 0;

		struct dnet_io_attr io;
		memset(&io, 0, sizeof(struct dnet_io_attr));

		struct dnet_id tmp;

		if (request->hasArg("from")) {
			dnet_parse_numeric_id(request->getArg("from"), tmp);
			memcpy(io.id, tmp.id, sizeof(io.id));
		}

		if (request->hasArg("to")) {
			dnet_parse_numeric_id(request->getArg("to"), tmp);
			memcpy(io.parent, tmp.id, sizeof(io.parent));
		} else {
			memset(io.parent, 0xff, sizeof(io.parent));
		}

		io.flags = ioflags;
		io.type = column;

		std::vector<struct dnet_io_attr> ret;

		for (size_t i = 0; i < groups.size(); ++i) {
			try {
				ret = sess.remove_data_range(io, groups[i], aflags);
				break;
			} catch (...) {
				continue;
			}
		}

		if (ret.size() == 0) {
			std::ostringstream str;
			str << filename.c_str() << ": REMOVE_RANGE failed in " << groups.size() << " groups";
			throw std::runtime_error(str.str());
		}

		std::string result;
		int removed = 0;

		for (size_t i = 0; i < ret.size(); ++i) {
			removed += ret[i].num;
		}

		result = boost::lexical_cast<std::string>(removed);

		request->setStatus(200);
		request->setContentType(content_type);
		request->setHeader("Content-Length", boost::lexical_cast<std::string>(result.length()));
		request->write(result.data(), result.size());
	}
	catch (const std::exception &e) {
		log()->error("%s: REMOVE_RANGE failed: %s", filename.c_str(), e.what());
		request->setStatus(404);
	}
	catch (...) {
		log()->error("%s: REMOVE_RANGE failed", filename.c_str());
		request->setStatus(404);
	}
}

void
EllipticsProxy::getHandler(fastcgi::Request *request) {
	std::string filename = request->hasArg("name") ? request->getArg("name") :
		request->getScriptName().substr(sizeof ("/get/") - 1, std::string::npos);

	ioremap::elliptics::session sess(*elliptics_node_);
	std::vector<int> groups;
	if (!metabase_write_addr_.empty() && !metabase_read_addr_.empty()) {
		try {
			groups = getMetaInfo(filename);
		}
		catch (...) {
			groups = getGroups(request);
		}
	}
	else {
		groups = getGroups(request);
	}

	std::string extention = filename.substr(filename.rfind('.') + 1, std::string::npos);

	if (deny_list_.find(extention) != deny_list_.end() ||
		(deny_list_.find("*") != deny_list_.end() &&
		allow_list_.find(extention) == allow_list_.end())) {
		throw fastcgi::HttpException(403);
	}

	std::map<std::string, std::string>::iterator it = typemap_.find(extention);

	std::string content_type;
	if (typemap_.end() == it) {
		content_type = "application/octet";
	}
	else {
		content_type = it->second;
	}

	try {
		sess.add_groups(groups);

		unsigned int aflags = request->hasArg("aflags") ? boost::lexical_cast<unsigned int>(request->getArg("aflags")) : 0;
		unsigned int ioflags = request->hasArg("ioflags") ? boost::lexical_cast<unsigned int>(request->getArg("ioflags")) : 0;
		int column = request->hasArg("column") ? boost::lexical_cast<int>(request->getArg("column")) : 0;
		uint64_t offset = request->hasArg("offset") ? boost::lexical_cast<uint64_t>(request->getArg("offset")) : 0;
		uint64_t size = request->hasArg("size") ? boost::lexical_cast<uint64_t>(request->getArg("size")) : 0;
		int latest = request->hasArg("latest") ? boost::lexical_cast<int>(request->getArg("latest")) : 0;

		std::string result;

		if (request->hasArg("id")) {
			struct dnet_id id;
			memset(&id, 0, sizeof(id));
			dnet_parse_numeric_id(request->getArg("id"), id);
			id.type = column;
			if (latest)
				result = sess.read_latest(id, offset, size, aflags, ioflags);
			else
				result = sess.read_data_wait(id, offset, size, aflags, ioflags);
		} else {
			if (latest)
				result = sess.read_latest(filename, offset, size, aflags, ioflags, column);
			else
				result = sess.read_data_wait(filename, offset, size, aflags, ioflags, column);
		}

		uint64_t ts = 0;
		if (request->hasArg("embed") || request->hasArg("embed_timestamp")) {
			size_t size = result.size();
			size_t offset = 0;

			while (size) {
				struct dnet_common_embed *e = (struct dnet_common_embed *)(result.data() + offset);

				dnet_common_convert_embedded(e);

				if (size < sizeof(struct dnet_common_embed)) {
					std::ostringstream str;
					str << filename << ": offset: " << offset << ", size: " << size << ": invalid size";
					throw std::runtime_error(str.str());
				}

				offset += sizeof(struct dnet_common_embed);
				size -= sizeof(struct dnet_common_embed);

				if (size < e->size + sizeof (struct dnet_common_embed)) {
					break;
				}

				if (e->type == DNET_FCGI_EMBED_TIMESTAMP) {
					uint64_t *ptr = (uint64_t *)e->data;

					ts = dnet_bswap64(ptr[0]);
				}

				if (e->type == DNET_FCGI_EMBED_DATA) {
					size = e->size;
					break;
				}

				if (e->type > DNET_FCGI_EMBED_TIMESTAMP) {
					int http_status = 200;
					bool allowed = true;
                                        for (size_t i = 0; i < embed_processors_.size(); i++) {
						if (embed_processors_[i].first == e->type) {
							log()->debug("Found embed processor for type %d", e->type);
							allowed = embed_processors_[i].second->processEmbed(request, *e, http_status);
							log()->debug("After embed processor http status %d, allowed %d", http_status, allowed);
						}
						if (!allowed) {
							request->setStatus(http_status);
							return;
						}
					}
				}

				offset += e->size;
				size -= e->size;
			}
			result = result.substr(offset, std::string::npos);
		}

		char ts_str[128];
		time_t timestamp = (time_t)(ts);
		struct tm tmp;
		strftime(ts_str, sizeof (ts_str), "%a, %d %b %Y %T %Z", gmtime_r(&timestamp, &tmp));

		if (request->hasHeader("If-Modified-Since")) {
			if (request->getHeader("If-Modified-Since") == ts_str) {
				request->setStatus(304);
				return;
			}
		}

		if (expires_ != 0) {
			char expires_str[128];
			timestamp = time(NULL) + expires_;
			strftime(expires_str, sizeof (expires_str), "%a, %d %b %Y %T %Z", gmtime_r(&timestamp, &tmp));
			request->setHeader("Expires", expires_str);
			request->setHeader("Cache-Control", "max-age=" + boost::lexical_cast<std::string>(expires_));
		}

		request->setStatus(200);
		request->setContentType(content_type);
		request->setHeader("Content-Length", boost::lexical_cast<std::string>(result.length()));
		request->setHeader("Last-Modified", ts_str);
		request->write(result.c_str(), result.size());
	}
	catch (const std::exception &e) {
		log()->error("can not locate file %s %s", filename.c_str(), e.what());
		request->setStatus(404);
	}
	catch (...) {
		log()->error("can not locate file %s", filename.c_str());
		request->setStatus(404);
	}
}

void
EllipticsProxy::statLogHandler(fastcgi::Request *request) {
	std::string result = "<?xml version=\"1.0\" encoding=\"utf-8\"?>";

	result += "<data>\n";

	ioremap::elliptics::session sess(*elliptics_node_);
	std::string ret = sess.stat_log();

	float la[3];
	const void *data = ret.data();
	int size = ret.size();
	char id_str[DNET_ID_SIZE * 2 + 1];
	char addr_str[128];

	while (size) {
		struct dnet_addr *addr = (struct dnet_addr *)data;
		struct dnet_cmd *cmd = (struct dnet_cmd *)(addr + 1);
		if (cmd->size != sizeof (struct dnet_stat)) {
			size -= cmd->size + sizeof (struct dnet_addr) + sizeof (struct dnet_cmd);
			data = (char *)data + cmd->size + sizeof (struct dnet_addr) + sizeof (struct dnet_cmd);
			continue;
		}
		struct dnet_stat *st = (struct dnet_stat *)(cmd+ 1);

		dnet_convert_stat(st);

		la[0] = (float)st->la[0] / 100.0;
		la[1] = (float)st->la[1] / 100.0;
		la[2] = (float)st->la[2] / 100.0;

		char buf[512];

		snprintf(buf, sizeof (buf), "<stat addr=\"%s\" id=\"%s\"><la>%.2f %.2f %.2f</la>"
			"<memtotal>%llu KB</memtotal><memfree>%llu KB</memfree><memcached>%llu KB</memcached>"
			"<storage_size>%llu MB</storage_size><available_size>%llu MB</available_size>"
			"<files>%llu</files><fsid>0x%llx</fsid></stat>",
			dnet_server_convert_dnet_addr_raw(addr, addr_str, sizeof(addr_str)),
			dnet_dump_id_len_raw(cmd->id.id, DNET_ID_SIZE, id_str),
			la[0], la[1], la[2],
			(unsigned long long)st->vm_total,
			(unsigned long long)st->vm_free,
			(unsigned long long)st->vm_cached,
			(unsigned long long)(st->frsize * st->blocks / 1024 / 1024),
			(unsigned long long)(st->bavail * st->bsize / 1024 / 1024),
			(unsigned long long)st->files, (unsigned long long)st->fsid);

		result += buf;

		int sz = cmd->size + sizeof (struct dnet_addr) + sizeof (struct dnet_cmd);
		size -= sz;
		data = (char *)data + sz;
	}

	result += "</data>";

	request->setStatus(200);
	request->write(result.c_str(), result.size());
}

void
EllipticsProxy::dnet_parse_numeric_id(const std::string &value, struct dnet_id &id)
{
	unsigned char ch[5];
	unsigned int i, len = value.size();
	const char *ptr = value.data();

	memset(id.id, 0, DNET_ID_SIZE);

	if (len/2 > DNET_ID_SIZE)
		len = DNET_ID_SIZE * 2;

	ch[0] = '0';
	ch[1] = 'x';
	ch[4] = '\0';
	for (i=0; i<len / 2; i++) {
		ch[2] = ptr[2*i + 0];
		ch[3] = ptr[2*i + 1];

		id.id[i] = (unsigned char)strtol((const char *)ch, NULL, 16);
	}

	if (len & 1) {
		ch[2] = ptr[2*i + 0];
		ch[3] = '0';

		id.id[i] = (unsigned char)strtol((const char *)ch, NULL, 16);
	}
}

void
EllipticsProxy::uploadHandler(fastcgi::Request *request) {
	ioremap::elliptics::session sess(*elliptics_node_);
	if (sess.state_num() < state_num_) {
		request->setStatus(403);
		return;
	}

	bool embed = request->hasArg("embed") || request->hasArg("embed_timestamp");
	struct timespec ts;
	ts.tv_sec = request->hasArg("timestamp") ? boost::lexical_cast<uint64_t>(request->getArg("timestamp")) : 0;
	ts.tv_nsec = 0;

	struct dnet_id id;
	memset(&id, 0, sizeof(id));

	unsigned int aflags = request->hasArg("aflags") ? boost::lexical_cast<unsigned int>(request->getArg("aflags")) : 0;
	unsigned int ioflags = request->hasArg("ioflags") ? boost::lexical_cast<unsigned int>(request->getArg("ioflags")) : 0;
	int column = request->hasArg("column") ? boost::lexical_cast<int>(request->getArg("column")) : 0;
	uint64_t offset = request->hasArg("offset") ? boost::lexical_cast<uint64_t>(request->getArg("offset")) : 0;

	std::string filename = request->hasArg("name") ? request->getArg("name") :
		request->getScriptName().substr(sizeof ("/upload/") - 1, std::string::npos);

	int replication_count = 0;
	int use_metabase = 0;
	if (request->hasArg("replication-count")) {
		try {
			replication_count = boost::lexical_cast<int>(request->getArg("replication-count"));
		}
		catch (...) {
			replication_count = 0;
		}
	}
	else {
		replication_count = replication_count_;
	}

	std::vector<int> groups = getGroups(request, replication_count);
#ifdef HAVE_METABASE
	if (metabase_socket_.get()) {
		if (request->hasArg("id")) {
			dnet_parse_numeric_id(request->getArg("id"), id);
		} else {
			sess.transform(filename, id);
		}

		std::vector<int> meta_groups = getMetabaseGroups(request, replication_count, id);
		if (meta_groups.size() > 0) {
			groups = meta_groups;
			use_metabase = 1;
		}
	}
	if (metabase_usage_ >= DNET_FCGI_META_NORMAL && !use_metabase) {
		std::string response("Metabase is not available or no suitable groups found");
		log()->error(response.c_str());
		request->setStatus(410);
		request->write(response.c_str(), response.length());
		return;
	}
#endif /* HAVE_METABASE */

	struct timeval start, stop;
	gettimeofday(&start, NULL);

	log()->debug("request %s initializing data buffer", request->getScriptName().c_str());

	fastcgi::DataBuffer buffer = request->requestBody();

	gettimeofday(&stop, NULL);

	log()->debug("request %s initialized data buffer spent %d", request->getScriptName().c_str(), (stop.tv_sec - start.tv_sec) * 1000000 +
		(stop.tv_usec - start.tv_usec));

	gettimeofday(&start, NULL);

	try {
		sess.add_groups(groups);

		bool chunked = false;
		boost::uint64_t chunk_offset = 0;
		boost::uint64_t write_offset;
		boost::uint64_t total_size = buffer.size();
		fastcgi::DataBuffer::SegmentIterator buffer_it, buffer_end;
		std::pair<char*, boost::uint64_t> chunk;

		std::string content;
		if (embed) {
			int size = sizeof (struct dnet_common_embed) * 2 + sizeof (uint64_t) * 2;

			char header[size];
			int err = dnet_common_prepend_data(&ts, buffer.size(), header, &size);
			if (err != 0) {
				throw std::runtime_error("bad data prepending");
			}
			content.append(header, size);
			total_size += content.size();
		}

		if (chunk_size_ && buffer.size() > (unsigned int)chunk_size_) {
			boost::uint64_t size = 0;
			chunked = true;
			content.reserve(chunk_size_ + content.size());
			for (buffer_it = buffer.begin(), buffer_end = buffer.end(); buffer_it != buffer_end; ++buffer_it, chunk_offset = 0) {
				size = chunk_size_;
				chunk = *buffer_it;
				log()->debug("chunk_offset: %llu, chunk: %x, end: %x", chunk_offset, chunk.first, buffer_end->first);
				if (chunk.second < size)
					size = chunk.second;
				content.append(chunk.first, size);
				chunk_offset += size;
				if (size >= (boost::uint64_t)chunk_size_)
					break;
			}
			if (chunk.second == size && size > 0) {
				++buffer_it;
				chunk_offset = 0;
			}
			log()->debug("after for chunk_offset: %llu, chunk: %x, end: %x", chunk_offset, chunk.first, buffer_end->first);
		} else {
			content.reserve(content.size() + buffer.size());
			for (fastcgi::DataBuffer::SegmentIterator it = buffer.begin(), end = buffer.end(); it != end; ++it) {
				std::pair<char*, boost::uint64_t> chunk = *it;
				content.append(chunk.first, chunk.second);
			}
		}

		int result = 0;
		std::string lookup;

		id.type = column;

		gettimeofday(&stop, NULL);

		log()->debug("request %s data prepared spent %d", request->getScriptName().c_str(), (stop.tv_sec - start.tv_sec) * 1000000 +
			(stop.tv_usec - start.tv_usec));

		gettimeofday(&start, NULL);

		try {
			if (request->hasArg("id")) {
				dnet_parse_numeric_id(request->getArg("id"), id);
				lookup = sess.write_data_wait(id, content, offset, aflags, ioflags);
			} else {
				sess.transform(filename, id);

				if (request->hasArg("prepare")) {
					uint64_t total_size_to_reserve = boost::lexical_cast<uint64_t>(request->getArg("prepare"));
					lookup = sess.write_prepare(filename, content, offset, total_size_to_reserve, aflags, ioflags, column);
				} else if (request->hasArg("commit")) {
					lookup = sess.write_commit(filename, content, offset, 0, aflags, ioflags, column);
				} else if (request->hasArg("plain_write")) {
					lookup = sess.write_plain(filename, content, offset, aflags, ioflags, column);
				} else {
					if (chunk_offset) {
						lookup = sess.write_prepare(filename, content, offset, total_size, aflags, ioflags, column);
					} else {
						lookup = sess.write_data_wait(filename, content, offset, aflags, ioflags, column);
					}
				}
			}
		}
		catch (const std::exception &e) {
			log()->error("bad id transform: %s", e.what());
		}
		catch (...) {
			log()->error("bad id transform: unknown");
		}

		if ((result == 0) && (lookup.size() == 0)) {
			log()->error("can not write file %s", filename.c_str());
			request->setStatus(503);
			return;
		}

		gettimeofday(&stop, NULL);

		log()->debug("request %s data written spent %d", request->getScriptName().c_str(), (stop.tv_sec - start.tv_sec) * 1000000 +
			(stop.tv_usec - start.tv_usec));

		struct dnet_id row;
		char id_str[2 * DNET_ID_SIZE + 1];
		char crc_str[2 * DNET_ID_SIZE + 1];

		sess.transform(content, row);
		dnet_dump_id_len_raw(id.id, DNET_ID_SIZE, id_str);
		dnet_dump_id_len_raw(row.id, DNET_ID_SIZE, crc_str);

		std::ostringstream ostr;

		ostr << "<?xml version=\"1.0\" encoding=\"utf-8\"?>" <<
			"<post obj=\"" << filename << "\" id=\"" << id_str <<
			"\" crc=\"" << crc_str << "\" groups=\"" << groups.size() <<
			"\" size=\"" << buffer.size() << "\">\n";

		log()->debug("string id %s", id_str);

		if (column != EBLOB_TYPE_DATA) {
			ostr << "<written>" << result << "</written>\n" <<
				"<!-- PLEASE NOTE THAT COLUMN WRITES DO NOT UPDATE METADATA AS " <<
				"WELL AS DO NOT CHECK NUMBER OF WRITTEN COPIES -->\n</post>";
			std::string response = ostr.str();

			request->setStatus(200);
			request->write(response.c_str(), response.length());
			return;
		}

		std::vector<int> temp_groups;
		if (replication_count != 0 && groups.size() != groups_.size() && !use_metabase) {
			for (std::size_t i = 0; i < groups_.size(); ++i) {
				if (groups.end() == std::find(groups.begin(), groups.end(), groups_[i])) {
					temp_groups.push_back(groups_[i]);
				}
			}
		}

		gettimeofday(&start, NULL);

		log()->debug("request %s writing copies", request->getScriptName().c_str());

		int written = 0;
		std::vector<int> upload_group;
		while (!written || written < replication_count) {
			long size = lookup.size();
			char *data = (char *)lookup.data();
			long min_size = sizeof(struct dnet_cmd) +
					sizeof(struct dnet_addr) +
					sizeof(struct dnet_addr_attr) +
					sizeof(struct dnet_file_info);

			while (size > min_size) {
				struct dnet_addr *addr = (struct dnet_addr *)data;
				struct dnet_cmd *cmd = (struct dnet_cmd *)(addr + 1);
				struct dnet_addr_attr *a = (struct dnet_addr_attr *)(cmd + 1);

				struct dnet_file_info *info = (struct dnet_file_info *)(a + 1);
				dnet_convert_file_info(info);

				char addr_dst[512];
				dnet_server_convert_dnet_addr_raw(addr, addr_dst, sizeof (addr_dst) - 1);

				upload_group.push_back(cmd->id.group_id);

				ostr << "<complete addr=\"" << addr_dst << "\" path=\"" <<
					(char *)(info + 1) << "\" group=\"" << cmd->id.group_id <<
					"\" status=\"" << cmd->status << "\"/>\n";

				++written;

				data += min_size + info->flen;
				size -= min_size + info->flen;
			}
			lookup.clear();
			log()->debug("written: %d", written);

			if (temp_groups.size() == 0 || (written && written >= replication_count) || use_metabase ) {
				break;
			}

			std::vector<int> try_group(1, 0);
			for (std::vector<int>::iterator it = temp_groups.begin(), end = temp_groups.end(); end != it; ++it) {
				try {
					log()->debug("writing to group %d", *it);
					try_group[0] = *it;
					sess.add_groups(try_group);

					if (chunked) {
						lookup = sess.write_plain(filename, content, offset, aflags, ioflags, column);
					} else {
						lookup = sess.write_data_wait(filename, content, offset, aflags, ioflags, column);
					}
				
					temp_groups.erase(it);
					break;
				} catch (...) {
					continue;
				}
			}
		}

		try {
			if (chunked) {
				sess.add_groups(upload_group);
				write_offset = offset + content.size();
				content.clear();
				log()->debug("chunk_offset: %llu, chunk: %x", chunk_offset, chunk.first);
				for (; buffer_it != buffer_end; ++buffer_it, chunk_offset = 0) {
					chunk = *buffer_it;
					while (chunk_offset < chunk.second) {
						log()->debug("    chunk_offset: %llu, chunk: %x", chunk_offset, chunk.first);
						boost::uint64_t size = chunk_size_;
						if ((chunk.second - chunk_offset) < size)
							size = chunk.second - chunk_offset;
						content.assign(chunk.first + chunk_offset, size);
						chunk_offset += size;

						lookup = sess.write_plain(filename, content, write_offset, aflags, ioflags, column);
						write_offset += size;
						content.clear();
					}
				}
			}
		} catch(const std::exception &e) {
			log()->error("error while uploading chunked data for file %s: %s", filename.c_str(), e.what());
			written = 0;
		} catch(...) {
			log()->error("error while uploading chunked data for file %s:", filename.c_str());
			written = 0;
		}

		log()->debug("written: %d", written);
		if (replication_count != 0 && written < replication_count) {
			try {
				sess.add_groups(groups_);
				sess.remove(filename);
				request->setStatus(410);
			}
			catch (...) {
				request->setStatus(409);
			}
			return;
		}

		gettimeofday(&stop, NULL);

		log()->debug("request %s copies written spent %d", request->getScriptName().c_str(), (stop.tv_sec - start.tv_sec) * 1000000 +
			(stop.tv_usec - start.tv_usec));

		if (replication_count == 0) {
			upload_group = groups_;
		}

		gettimeofday(&start, NULL);

		log()->debug("request %s writing metadata", request->getScriptName().c_str());

		sess.write_metadata(id, filename, upload_group, ts, 0);

		gettimeofday(&stop, NULL);

		log()->debug("request %s metadata written spent %d", request->getScriptName().c_str(), (stop.tv_sec - start.tv_sec) * 1000000 +
			(stop.tv_usec - start.tv_usec));

		if (!metabase_write_addr_.empty() && !metabase_read_addr_.empty()) {
			uploadMetaInfo(groups, filename);
		}


		sess.add_groups(groups_);

		ostr << "<written>" << written << "</written>\n</post>";

		gettimeofday(&start, NULL);

		log()->debug("request %s preparing response", request->getScriptName().c_str());

		std::string response = ostr.str();

		if (replication_count == 0 && written < success_copies_num_) {
			log()->error("can not write file %s %d copies instead %d", filename.c_str(), written, success_copies_num_);
			request->setStatus(403);
		}
		else {
			request->setStatus(200);
		}

		char check[DNET_ID_SIZE];
		memset(check, 0, sizeof (check));

		if (!memcmp(id.id, check, sizeof (check))) {
			log()->error("POSIBLE ZERO KEY ERROR! handler: %s query: %s replication_count: %d written_copies: %d",
				request->getScriptName().c_str(),
				request->getQueryString().c_str(),
				replication_count,
				written);
			throw std::runtime_error("ZERO KEY!");
		}

		gettimeofday(&stop, NULL);

		log()->debug("request %s response written spent %d", request->getScriptName().c_str(), (stop.tv_sec - start.tv_sec) * 1000000 +
			(stop.tv_usec - start.tv_usec));

		request->write(response.c_str(), response.length());
	}
	catch (const std::exception &e) {
		log()->error("can not write file %s %s", filename.c_str(), e.what());
		request->setStatus(503);
	}
	catch (...) {
		log()->error("can not write file %s", filename.c_str());
		request->setStatus(503);
	}
}

void
EllipticsProxy::deleteHandler(fastcgi::Request *request) {
	ioremap::elliptics::session sess(*elliptics_node_);
	if (sess.state_num() < state_num_) {
		request->setStatus(403);
		return;
	}

	std::string filename = request->hasArg("name") ? request->getArg("name") :
		request->getScriptName().substr(sizeof ("/delete/") - 1, std::string::npos);

	std::vector<int> groups;
	if (!metabase_write_addr_.empty() && !metabase_read_addr_.empty()) {
		try {
			groups = getMetaInfo(filename);
		}
		catch (...) {
			groups = getGroups(request);
		}
	}
	else {
		groups = getGroups(request);
	}

	try {
		sess.add_groups(groups);
		if (request->hasArg("id")) {
			int error = -1;
			struct dnet_id id;
			memset(&id, 0, sizeof(id));

			dnet_parse_numeric_id(request->getArg("id"), id);

			for (size_t i = 0; i < groups.size(); ++i) {
				id.group_id = groups[i];
				try {
					sess.remove(id);
					error = 0;
				} catch (const std::exception &e) {
					log()->error("can not delete file %s in group %d: %s", filename.c_str(), groups[i], e.what());
				}
			}

			if (error) {
				std::ostringstream str;
				str << dnet_dump_id(&id) << ": REMOVE failed";
				throw std::runtime_error(str.str());
			}
		} else {
			sess.remove(filename);
		}
		request->setStatus(200);
	}
	catch (const std::exception &e) {
		log()->error("can not delete file %s %s", filename.c_str(), e.what());
		request->setStatus(503);
	}
	catch (...) {
		log()->error("can not write file %s", filename.c_str());
		request->setStatus(504);
	}
}

void
EllipticsProxy::bulkReadHandler(fastcgi::Request *request) {

	ioremap::elliptics::session sess(*elliptics_node_);

	typedef boost::char_separator<char> Separator;
	typedef boost::tokenizer<Separator> Tokenizer;

	std::vector<int> groups;
	groups = getGroups(request);

	std::string content_type = "application/octet";

	try {
		unsigned int aflags = request->hasArg("aflags") ? boost::lexical_cast<unsigned int>(request->getArg("aflags")) : 0;
		//unsigned int ioflags = request->hasArg("ioflags") ? boost::lexical_cast<unsigned int>(request->getArg("ioflags")) : 0;
		//int column = request->hasArg("column") ? boost::lexical_cast<int>(request->getArg("column")) : 0;
		int group_id = request->hasArg("group_id") ? boost::lexical_cast<int>(request->getArg("group_id")) : 0;
		std::string key_type = request->hasArg("key_type") ? request->getArg("key_type") : "name";

		if (group_id <= 0) {
			std::ostringstream str;
			str << "BULK_READ failed: group_id is mandatory and it should be > 0";
			throw std::runtime_error(str.str());
		}

		sess.add_groups(groups);

		std::vector<std::string> ret;

		if (key_type.compare("name") == 0) {
			// body of POST request contains lines with file names
			std::vector<std::string> keys;

			// First, concatenate it
			std::string content;
			request->requestBody().toString(content);

			/*content.reserve(buffer.size());
			for (fastcgi::DataBuffer::SegmentIterator it = buffer.begin(), end = buffer.end(); it != end; ++it) {
				std::pair<char*, boost::uint64_t> chunk = *it;
				content.append(chunk.first, chunk.second);
			}*/

			// Then parse to extract key names
			Separator sep(" \n");
			Tokenizer tok(content, sep);

			for (Tokenizer::iterator it = tok.begin(), end = tok.end(); end != it; ++it) {
				log()->debug("BULK_READ: adding key %s", it->c_str());
				keys.push_back(*it);
			}

			// Finally, call bulk_read method
			ret = sess.bulk_read(keys, aflags);

		} else {
			std::ostringstream str;
			str << "BULK_READ failed: unsupported key type " << key_type;
			throw std::runtime_error(str.str());
		}

		if (ret.size() == 0) {
			std::ostringstream str;
			str << "BULK_READ failed: zero size reply";
			throw std::runtime_error(str.str());
		}

		std::string result;

		for (size_t i = 0; i < ret.size(); ++i) {
			result += ret[i];
		}

		request->setStatus(200);
		request->setContentType(content_type);
		request->setHeader("Content-Length", boost::lexical_cast<std::string>(result.length()));
		request->write(result.data(), result.size());
	}
	catch (const std::exception &e) {
		log()->error("BULK_READ failed: %s", e.what());
		request->setStatus(404);
	}
	catch (...) {
		log()->error("BULK_READ failed");
		request->setStatus(404);
	}
}

struct bulk_file_info_single {
	std::string addr;
	std::string path;
	int group;
	int status;
};

struct bulk_file_info {
	char id[2 * DNET_ID_SIZE + 1];
	char crc[2 * DNET_ID_SIZE + 1];
	boost::uint64_t size;

	std::vector<struct bulk_file_info_single> groups;
};
	

void
EllipticsProxy::bulkWriteHandler(fastcgi::Request *request) {

	ioremap::elliptics::session sess(*elliptics_node_);

	std::vector<int> groups;
	groups = getGroups(request);

	std::string content_type = "application/octet";

	try {
		unsigned int aflags = request->hasArg("aflags") ? boost::lexical_cast<unsigned int>(request->getArg("aflags")) : 0;
		unsigned int ioflags = request->hasArg("ioflags") ? boost::lexical_cast<unsigned int>(request->getArg("ioflags")) : 0;
		int column = request->hasArg("column") ? boost::lexical_cast<int>(request->getArg("column")) : 0;
		int group_id = request->hasArg("group_id") ? boost::lexical_cast<int>(request->getArg("group_id")) : 0;
		std::string key_type = request->hasArg("key_type") ? request->getArg("key_type") : "id";

		if (group_id <= 0) {
			std::ostringstream str;
			str << "BULK_WRITE failed: group_id is mandatory and it should be > 0";
			throw std::runtime_error(str.str());
		}

		sess.add_groups(groups);

		std::string lookup;
		std::ostringstream ostr;
		std::map<std::string, struct bulk_file_info> results;

		if (key_type.compare("id") == 0) {

			std::vector<struct dnet_io_attr> ios;
			struct dnet_io_attr io;
			std::vector<std::string> data;
			std::string empty;
			boost::uint64_t pos = 0, data_readed;

			fastcgi::DataBuffer buffer = request->requestBody();

			struct dnet_id row;
			std::string id;

			while (pos < buffer.size()) {
				memset(&io, 0, sizeof(io));
				io.flags = ioflags;
				io.type = column;

				data_readed = buffer.read(pos, (char *)io.id, DNET_ID_SIZE);
				if (data_readed != DNET_ID_SIZE) {
					std::ostringstream str;
					str << "BULK_WRITE failed: read " << data_readed << ", " << DNET_ID_SIZE << " bytes needed ";
					throw std::runtime_error(str.str());
				}
				pos += DNET_ID_SIZE;

				data_readed = buffer.read(pos, (char *)&io.size, sizeof(io.size));
				if (data_readed != sizeof(io.size)) {
					std::ostringstream str;
					str << "BULK_WRITE failed: read " << data_readed << ", " << sizeof(io.size) << " bytes needed ";
					throw std::runtime_error(str.str());
				}
				if (io.size > (buffer.size() - pos)) {
					std::ostringstream str;
					str << dnet_dump_id_str(io.id) << ": BULK_WRITE failed: size of data is " << io.size 
						<< " but buffer size is " << (buffer.size() - pos);
				}
				pos += sizeof(io.size);

				boost::scoped_array<char> tmp_buffer(new char[io.size]);
				data_readed = buffer.read(pos, tmp_buffer.get(), io.size);
				if (data_readed != io.size) {
					std::ostringstream str;
					str << dnet_dump_id_str(io.id) << ": BULK_WRITE failed: read " << data_readed << ", " << io.size << " bytes needed ";
					throw std::runtime_error(str.str());
				}
				pos += io.size;

				ios.push_back(io);
				data.push_back(empty);
				data.back().assign(tmp_buffer.get(), io.size);

				struct bulk_file_info file_info;

				sess.transform(tmp_buffer.get(), row);
				dnet_dump_id_len_raw(io.id, DNET_ID_SIZE, file_info.id);
				dnet_dump_id_len_raw(row.id, DNET_ID_SIZE, file_info.crc);
				file_info.size = io.size;

				id.assign(file_info.id);
				results[id] = file_info;
			}

			lookup = sess.bulk_write(ios, data, aflags);

		} else {
			std::ostringstream str;
			str << "BULK_WRITE failed: unsupported key type " << key_type;
			throw std::runtime_error(str.str());
		}


		ostr << "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n";

		long size = lookup.size();
		char *data = (char *)lookup.data();
		long min_size = sizeof(struct dnet_cmd) +
				sizeof(struct dnet_addr) +
				sizeof(struct dnet_addr_attr) +
				sizeof(struct dnet_file_info);

		char addr_dst[512];
		char id_str[2 * DNET_ID_SIZE + 1];
		struct bulk_file_info_single file_info;
		std::string id;

		while (size > min_size) {
			struct dnet_addr *addr = (struct dnet_addr *)data;
			struct dnet_cmd *cmd = (struct dnet_cmd *)(addr + 1);
			struct dnet_addr_attr *a = (struct dnet_addr_attr *)(cmd + 1);

			struct dnet_file_info *info = (struct dnet_file_info *)(a + 1);
			dnet_convert_file_info(info);

			dnet_server_convert_dnet_addr_raw(addr, addr_dst, sizeof (addr_dst) - 1);

			dnet_dump_id_len_raw(cmd->id.id, DNET_ID_SIZE, id_str);
			id.assign(id_str);

			file_info.addr.assign(addr_dst);
			file_info.path.assign((char *)(info + 1));
			file_info.group = cmd->id.group_id;
			file_info.status = cmd->status;

			results[id].groups.push_back(file_info);


			data += min_size + info->flen;
			size -= min_size + info->flen;
		}
		lookup.clear();

		for (std::map<std::string, struct bulk_file_info>::iterator it = results.begin(); it != results.end(); it++) {
			ostr << "<post obj=\"\" id=\"" << it->first <<
				"\" crc=\"" << it->second.crc << "\" groups=\"" << groups.size() <<
				"\" size=\"" << it->second.size << "\">\n" <<
				"	<written>\n";

			for (std::vector<struct bulk_file_info_single>::iterator gr_it = it->second.groups.begin();
					gr_it != it->second.groups.end(); gr_it++) {
				ostr << "		<complete addr=\"" << gr_it->addr << "\" path=\"" <<
					gr_it->path << "\" group=\"" << gr_it->group <<
					"\" status=\"" << gr_it->status << "\"/>\n";
			}
			ostr << "	</written>\n</post>\n";
		}

		std::string result = ostr.str();

		request->setStatus(200);
		request->setContentType(content_type);
		request->setHeader("Content-Length", boost::lexical_cast<std::string>(result.length()));
		request->write(result.data(), result.size());
	}
	catch (const std::exception &e) {
		log()->error("BULK_WRITE failed: %s", e.what());
		request->setStatus(404);
	}
	catch (...) {
		log()->error("BULK_WRITE failed");
		request->setStatus(404);
	}
}

void
EllipticsProxy::execScriptHandler(fastcgi::Request *request) {
	ioremap::elliptics::session sess(*elliptics_node_);
	if (sess.state_num() < state_num_) {
		request->setStatus(403);
		return;
	}

	struct dnet_id id;
	memset(&id, 0, sizeof(id));

	std::string filename = request->hasArg("name") ? request->getArg("name") :
		request->getScriptName().substr(sizeof ("/exec-script/") - 1, std::string::npos);

	if (request->hasArg("id")) {
		dnet_parse_numeric_id(request->getArg("id"), id);
	} else {
		sess.transform(filename, id);
	}

	std::string script = request->hasArg("script") ? request->getArg("script") : "";

	std::vector<int> groups;
	groups = getGroups(request);
	std::string ret;

	try {
		log()->debug("script is <%s>", script.c_str());

		sess.add_groups(groups);

		std::string content;
		request->requestBody().toString(content);


		ret = sess.exec_locked(&id, script, content, std::string());

	}
	catch (const std::exception &e) {
		log()->error("can not execute script %s %s", script.c_str(), e.what());
		request->setStatus(503);
	}
	catch (...) {
		log()->error("can not execute script %s", script.c_str());
		request->setStatus(503);
	}
	request->setStatus(200);
	request->write(ret.data(), ret.size());
}

std::vector<int>
EllipticsProxy::getGroups(fastcgi::Request *request, size_t count) const {
	std::vector<int> groups;

	if (request->hasArg("groups")) {
		Separator sep(":");
		Tokenizer tok(request->getArg("groups"), sep);

		try {
			for (Tokenizer::iterator it = tok.begin(), end = tok.end(); end != it; ++it) {
				groups.push_back(boost::lexical_cast<int>(*it));
			}
		}
		catch (...) {
			throw fastcgi::HttpException(503);
		}
	}
	else {
		groups = groups_;
		std::vector<int>::iterator git = groups.begin();
		++git;
		std::random_shuffle(git, groups.end());
	}

	if (count != 0 && count < groups.size()) {
		groups.erase(groups.begin() + count, groups.end());
	}

	return groups;
}

void
EllipticsProxy::uploadMetaInfo(const std::vector<int> &groups, const std::string &filename) const {
	try {
		std::string url = metabase_write_addr_ + "/groups-meta." + filename + ".txt";
		yandex::common::curl_wrapper<yandex::common::boost_threading_traits> curl(url);
		curl.header("Expect", "");
		curl.timeout(10);

		std::string result;
		for (std::size_t i = 0; i < groups.size(); ++i) {
			if (!result.empty()) {
				result += ':';
			}
			result += boost::lexical_cast<std::string>(groups[i]);
		}

		std::stringstream response;
		long status = curl.perform_post(response, result);
		if (200 != status) {
			throw fastcgi::HttpException(403);
		}
	}
	catch (const fastcgi::HttpException &e) {
		throw;
	}
	catch (...) {
		throw fastcgi::HttpException(403);
	}
}

std::vector<int>
EllipticsProxy::getMetaInfo(const std::string &filename) const {
	try {
		std::stringstream response;
		long status;

		std::string url = metabase_read_addr_ + "/groups-meta." + filename + ".txt";
		yandex::common::curl_wrapper<yandex::common::boost_threading_traits> curl(url);
		curl.header("Expect", "");
		curl.timeout(10);
		status = curl.perform(response);

		if (200 != status) {
			throw fastcgi::NotFound();
		}

		std::vector<int> groups;

		Separator sep(":");
		Tokenizer tok(response.str(), sep);

		for (Tokenizer::iterator it = tok.begin(), end = tok.end(); end != it; ++it) {
			groups.push_back(boost::lexical_cast<int>(*it));
		}

		return groups;
	}
	catch (const fastcgi::HttpException &e) {
		throw;
	}
	catch (...) {
		throw fastcgi::HttpException(403);
	}
}

#ifdef HAVE_METABASE
std::vector<int> 
EllipticsProxy::getMetabaseGroups(fastcgi::Request *request, size_t count, struct dnet_id &id) {
	std::vector<int> groups;
	int rc = 0;

	log()->debug("Requesting metabase for %d groups for upload, metabase_usage: %d", count, metabase_usage_);

	if (metabase_usage_ == DNET_FCGI_META_NORMAL && request->hasArg("groups")) {
		groups = getGroups(request, count);
		count = groups.size();
		return groups;
	}

	if (count <= 0)
		return groups;

	if (!metabase_socket_.get())
		return groups;

	MetabaseRequest req;
	req.groups_num = count;
	req.stamp = ++metabase_current_stamp_;
	req.id.assign(id.id, id.id+DNET_ID_SIZE);

	msgpack::sbuffer buf;
	msgpack::pack(buf, req);

	zmq::message_t empty_msg;
	zmq::message_t req_msg(buf.size());
	memcpy(req_msg.data(), buf.data(), buf.size());

	try {
		if (!metabase_socket_->send(empty_msg, ZMQ_SNDMORE)) {
			log()->error("error during zmq send empty");
			return groups;
		}
		if (!metabase_socket_->send(req_msg)) {
			log()->error("error during zmq send");
			return groups;
		}
	} catch(const zmq::error_t& e) {
		log()->error("error during zmq send: %s", e.what());
		return groups;
	}

	zmq::pollitem_t items[] = {
		{ *metabase_socket_, 0, ZMQ_POLLIN, 0 }
	};

	rc = 0;

	try {
		rc = zmq::poll(items, 1, metabase_timeout_);
	} catch(const zmq::error_t& e) {
		log()->error("error during zmq poll: %s", e.what());
		return groups;
	} catch (...) {
		log()->error("error during zmq poll");
		return groups;
	}

	if (rc == 0) {
		log()->error("error: no answer from zmq");
	} else if (items[0].revents && ZMQ_POLLIN) {
		zmq::message_t msg;
		MetabaseResponse resp;
		msgpack::unpacked unpacked;

		try {
			resp.stamp = 0;
			while (resp.stamp < metabase_current_stamp_) {
				if (!metabase_socket_->recv(&msg, ZMQ_NOBLOCK)) {
					break;
				}
				if (!metabase_socket_->recv(&msg, ZMQ_NOBLOCK)) {
					break;
				}

				msgpack::unpack(&unpacked, static_cast<const char*>(msg.data()), msg.size());
				unpacked.get().convert(&resp);
				log()->debug("current stamp is %d", resp.stamp);
			}
		} catch(const msgpack::unpack_error &e) {
			log()->error("error during msgpack::unpack: %s", e.what());
			return groups;
		} catch(...) {
			log()->error("error during msgpack::unpack");
			return groups;
		}

		return resp.groups;
	} else {
		log()->error("error after zmq poll: %d", rc);
	}

	return groups;
}
#endif /* HAVE_METABASE */

size_t
EllipticsProxy::paramsNum(Tokenizer &tok) {
	size_t result = 0;
	for (Tokenizer::iterator it = ++tok.begin(), end = tok.end(); end != it; ++it) {
		++result;
	}
	return result;
}

FCGIDAEMON_REGISTER_FACTORIES_BEGIN()
FCGIDAEMON_ADD_DEFAULT_FACTORY("elliptics-proxy", EllipticsProxy);
FCGIDAEMON_REGISTER_FACTORIES_END()

} // namespace elliptics

