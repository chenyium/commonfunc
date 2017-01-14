#include <string>
#include <vector>

#ifndef __COMMON_UNIT_H__
#define __COMMON_UNIT_H__

//! automatic delete array point
/*! \author chenyao
 */
template <typename type> class CArrayPoint
{
public:
	explicit CArrayPoint(int size) {
		m_capacity = size;
		m_point = new type[size]();
	}
	~CArrayPoint() {
		delete[] m_point, m_point = NULL;
	}

private:
	CArrayPoint(CArrayPoint&);
	CArrayPoint& operator =(CArrayPoint&);

public:
	operator type*() const { return m_point; }

public:
	inline int capacity() { return m_capacity; }

private:
	type * m_point;
	int m_capacity;
};

class IResolve 
{
public:
	virtual ~IResolve() {}
	virtual void invoke() = 0;
	virtual const std::vector<std::string> & value() const = 0;
	virtual const std::string next() = 0;
};

class CResolveArray : public IResolve 
{
public:
	CResolveArray(const std::string & _origin, const std::string & _delimit) 
			: m_origin(_origin), m_delimit(_delimit) {
		m_iterator = m_gather.begin();
	}

	virtual void invoke() {
		char * token = NULL;
		char * state = NULL;

		CArrayPoint<char> buffer(m_origin.length() + 1);
		strcpy_s(buffer, buffer.capacity(), m_origin.c_str());

		token = strtok_s(buffer, m_delimit.c_str(), &state);

		while (NULL != token) {
			m_gather.push_back(token);
			token = strtok_s(NULL, m_delimit.c_str(), &state);
		}

		m_iterator = m_gather.begin();
	}

	virtual const std::vector<std::string> & value() const { return m_gather; }

	virtual const std::string next() {
		if (m_iterator == m_gather.end()) {
			return std::string("");
		}

		return *m_iterator++;
	}

private:
	std::vector<std::string> m_gather;
	std::vector<std::string>::iterator m_iterator;
	std::string m_origin;
	std::string m_delimit;
};

#endif