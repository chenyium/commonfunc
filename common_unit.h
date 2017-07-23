#include <string>
#include <vector>
#include <queue>

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

template <typename T> class CResolveArrayTL 
{
public:
	CResolveArrayTL(const T * _origin, int length, const T * _delimit) 
			: m_origin(length + 1), m_delimit(_delimit) {
		memcpy_s(m_origin, sizeof(T) * m_origin.capacity(), _origin, sizeof(T) * (length));
	}

	void invoke() {}
	const T * next() { return obtain(); }
	bool hasNext() { return !m_queue.empty(); }

private:
	const T * obtain() {
		if (m_queue.empty()) return static_cast<T *>(0);
		const T * temp = m_queue.front(); m_queue.pop();
		return temp;
	}

private:
	std::queue<T *> m_queue;
	const T * m_delimit;
	CArrayPoint<T> m_origin;
};

void CResolveArrayTL<wchar_t>::invoke() {
	wchar_t * state = NULL;
	wchar_t * token = wcstok_s(m_origin, m_delimit, &state);
	while (token) {
		m_queue.push(token);
		token = wcstok_s(NULL, m_delimit, &state);
	}
}

void CResolveArrayTL<char>::invoke() {
	char * state = NULL;
	char * token = strtok_s(m_origin, m_delimit, &state);
	while (token) {
		m_queue.push(token);
		token = strtok_s(NULL, m_delimit, &state);
	}
}

#pragma warning (push)
#pragma warning (disable:4706)
const wchar_t * CResolveArrayTL<wchar_t>::next() {
	const wchar_t * temp;
	return (temp = obtain()) ? temp : L"";
}

const char * CResolveArrayTL<char>::next() {
	const char * temp;
	return (temp = obtain()) ? temp : "";
}
#pragma warning (pop)

template <typename T> class CSingleton 
{
protected:
	CSingleton() {}
	virtual ~CSingleton() {}

private:
	CSingleton(CSingleton &);
	CSingleton & operator=(const CSingleton &);

protected:
	class CGarbo {
	public:
		~CGarbo() { if (CSingleton::m_instance) delete CSingleton::m_instance; }
	};
	static CGarbo m_garbo;

private:
	static T * m_instance;

public:
	static T * Instance() {
		// create T instance. m_garbo must be here
		if (nullptr == m_instance) { m_instance = new T; } 
		m_garbo.CGarbo::CGarbo();
		return m_instance;
	}
};
template <typename T> T * CSingleton<T>::m_instance = nullptr;
template <typename T> typename CSingleton<T>::CGarbo CSingleton<T>::m_garbo;

#endif