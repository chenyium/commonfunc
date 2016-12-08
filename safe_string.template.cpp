#include <windows.h>
#include <wchar.h>
#include <stdarg.h>

// C++ only
template <size_t size>
int _cdecl safe_sprintf(char (&buffer)[size],
		const char *format, ...)
{
	memset(buffer, 0, size * sizeof(char));

	if (NULL == format)
		return -1;

	va_list ap;
	va_start(ap, format);

	int res = -1;
	res = _vsnprintf_s(buffer, size, _TRUNCATE, 
				format, ap);

	va_end(ap);

	return res;
}

// C++ only
template <size_t size>
int _cdecl safe_sprintf(wchar_t (&buffer)[size],
		const wchar_t *format, ...)
{
	memset(buffer, 0, size * sizeof(wchar_t));

	if (NULL == format)
		return -1;

	va_list ap;
	va_start(ap, format);

	int res = -1;
	res = _vsnwprintf_s(buffer, size, _TRUNCATE, 
				format, ap);

	va_end(ap);

	return res;
}

// C++ only
template <size_t size>
int _cdecl safe_overwrite(char (&buffer)[size],
		const char *format, ...)
{
	if (NULL == format)
		return -1;

	char *interim = (char*) calloc(size, sizeof(char));

	va_list ap;
	va_start(ap, format);

	int res = -1;
	res = _vsnprintf_s(interim, size, _TRUNCATE,
				format, ap);

	va_end(ap);

	memset(buffer, 0, size * sizeof(char));
	memcpy(buffer, interim, size);

	free(interim), interim = NULL;
	return res;
}

// C++ only
template <size_t size>
int _cdecl safe_overwrite(wchar_t (&buffer)[size],
		const wchar_t *format, ...)
{
	if (NULL == format)
		return -1;

	wchar_t *interim = (wchar_t*) calloc(size, sizeof(wchar_t));

	va_list ap;
	va_start(ap, format);

	int res = -1;
	res = _vsnwprintf_s(interim, size, _TRUNCATE,
				format, ap);

	va_end(ap);

	wmemset(buffer, 0, size);
	wmemcpy(buffer, interim, size);

	free(interim), interim = NULL;
	return res;
}
