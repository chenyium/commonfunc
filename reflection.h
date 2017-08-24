#ifndef __RUNTIME_REFLECT_H__
#define __RUNTIME_REFLECT_H__

/*!
example:
	class CRecordSuper {
		DECLARE_REFLECT_BASE(CRecordSuper)
	};
	IMPLEMENT_REFLECT_BASE(CRecordSuper)

	class CRecordPass : public CRecordSuper {
		DECLARE_RUNTIME_REFLECT(CRecordPass, CRecordSuper)
	};
	IMPLEMENT_RUNTIME_REFLECT(CRecordPass, CRecordSuper)

	CRecordSuper * super = CRuntimeReflect<CRecordSuper>::CreateObject(L"CRecordPass");
	if (NULL == super) ...
	...
	delete super, super = NULL;

*/

//! author : chenyao (cheny@meizu.com)

#undef RUNTIME_REFLECT
#define RUNTIME_REFLECT(class_name, class_base) \
	((CRuntimeReflect<class_base> *)(&class_name::reflect##class_name))

#undef DECLARE_REFLECT_BASE
#define DECLARE_REFLECT_BASE(class_name) \
	public: \
	static CRuntimeReflect<class_name> reflect##class_name; \
	virtual CRuntimeReflect<class_name> * GetRuntimeReflect();

#undef IMPLEMENT_REFLECT_BASE
#define IMPLEMENT_REFLECT_BASE(class_name) \
    CRuntimeReflect<class_name> class_name::reflect##class_name = \
		{ L###class_name, NULL, NULL }; \
    CRuntimeReflect<class_name> * class_name::GetRuntimeReflect() \
        { return RUNTIME_REFLECT(class_name, class_name); } \
    RUNTIME_REFLECT_INIT<class_name> _init_reflect_##class_name(RUNTIME_REFLECT(class_name, class_name));

#undef DECLARE_RUNTIME_REFLECT
#define DECLARE_RUNTIME_REFLECT(class_name, class_base) \
    public: \
    static class_base * CreateReflect(); \
	static CRuntimeReflect<class_base> reflect##class_name; \
	virtual CRuntimeReflect<class_base> * GetRuntimeReflect();

#undef IMPLEMENT_RUNTIME_REFLECT
#define IMPLEMENT_RUNTIME_REFLECT(class_name, class_base) \
    class_base * class_name::CreateReflect() \
        { return dynamic_cast<class_base *>(new class_name); } \
    CRuntimeReflect<class_base> class_name::reflect##class_name = \
		{ L###class_name, class_name::CreateReflect, NULL }; \
    CRuntimeReflect<class_base> * class_name::GetRuntimeReflect() \
        { return RUNTIME_REFLECT(class_name, class_base); } \
    RUNTIME_REFLECT_INIT<class_base> _init_reflect_##class_name(RUNTIME_REFLECT(class_name, class_base));

template <class T> struct CRuntimeReflect {
	const wchar_t * m_className;
	T * (* m_createObject)();
	T * CreateObject();
	static CRuntimeReflect * FromName(const wchar_t * className);
	static T * CreateObject(const wchar_t * className);
	static CRuntimeReflect * m_firstClass;
	CRuntimeReflect * m_nextClass;       // linked list of registered classes
};

template <class T> struct RUNTIME_REFLECT_INIT {
	RUNTIME_REFLECT_INIT(CRuntimeReflect<T> * newClass) { 
		newClass->m_nextClass = CRuntimeReflect<T>::m_firstClass;
		CRuntimeReflect<T>::m_firstClass = newClass;
	}
};

template <class T>
CRuntimeReflect<T> * CRuntimeReflect<T>::m_firstClass = NULL;

template <class T>
T * CRuntimeReflect<T>::CreateObject() {
	return NULL == m_createObject ? NULL : (* m_createObject)();
}

template <class T>
CRuntimeReflect<T> * CRuntimeReflect<T>::FromName(const wchar_t * className) {
	for (CRuntimeReflect * iter = CRuntimeReflect::m_firstClass; 
			NULL != iter; iter = iter->m_nextClass)
		if (0 == wcscmp(className, iter->m_className)) return iter;
	return NULL;
}

template <class T>
T * CRuntimeReflect<T>::CreateObject(const wchar_t * className) {
	CRuntimeReflect * runtime = FromName(className);
	return NULL == runtime ? NULL : runtime->CreateObject();
}

#endif
