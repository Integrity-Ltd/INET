#ifndef INET_HH_
#define INET_HH_

#include <boost/asio/ip/address.hpp>

using boost::asio::ip::address;
using boost::asio::ip::address_v4;
using boost::asio::ip::address_v6;

class INET;
class ARPA;

class ARPA {
	std::string arpa_;
public:
	ARPA(const std::string &);
	ARPA(const INET &);
	std::string to_ip_string() const;
	std::string get() const;
};

class INET {
public:
	enum Type {
		ipv4 = 4, ipv6 = 6
	};
private:
	Type type_;
	address_v4 ipv4_address_;
	unsigned long ipv4_mask_ = 0;
	address_v6 ipv6_address_;
	address_v6::bytes_type ipv6_mask_;
	uint64_t masklen_ = 0;

	inline void set_ip4_(const address_v4 &, uint64_t subnet = 32);
	inline void set_ip6_(const address_v6 &, uint64_t subnet = 128);
	void init_mask_(uint64_t subnet);

	void set_equal_to_(const INET &);
	void set_equal_to_(const address &);
	void set_equal_to_(const address_v4 &);
	void set_equal_to_(const address_v6 &);
	void set_equal_to_(const std::string &);
	void set_equal_to_(const ARPA &);

public:

	INET(const std::string &);
	INET(const ARPA &);
	INET(const address &, uint64_t);
	INET(const address_v4 &, uint64_t subnet = 32);
	INET(const address_v6 &, uint64_t subnet = 128);
	INET(const INET &);

	INET & operator=(const INET &);
	INET & operator=(const address &);
	INET & operator=(const address_v4 &);
	INET & operator=(const address_v6 &);
	INET & operator=(const std::string &);
	INET & operator=(const ARPA &);

//	INET(INET &&);
//	INET & operator=(INET &&);

	std::string to_string(bool show_mask = true) const;
	std::string to_arpa() const;

	uint64_t get_subnet() const;
	void set_subnet(uint64_t);
	std::string get_subnet_string() const;
	void set_subnet_string(const std::string &);

	bool operator==(const INET &) const;
	bool operator!=(const INET &) const;
	bool operator<(const INET &) const;
	bool operator<=(const INET &) const;
	bool operator>(const INET &) const;
	bool operator>=(const INET &) const;

	// is contained within
	bool operator<<(const INET &) const;
	bool operator<<=(const INET &) const;

	// is contains
	bool operator>>(const INET &) const;
	bool operator>>=(const INET &) const;

	operator std::string() const {
		return to_string();
	}

//	friend INET operator~(const INET &);
//
//	INET operator&(const INET &) const;
//	INET operator|(const INET &) const;
//
//	INET broadcast() const;
//	INET abbrev() const;

	address_v4 to_v4() const;
	address_v6 to_v6() const;

	Type get_type() const;

	bool is_ip4() const;
	bool is_ip6() const;
};

std::string to_ipv4_string(uint32_t);

#endif /* INET_HH_ */
