/***
 * ==++==
 *
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * ==--==
 * =+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
 *
 * HTTP Library: Client-side APIs.
 *
 * This file contains a cross platform implementation based on Boost.ASIO.
 *
 * For the latest on this and related APIs, please see http://casablanca.codeplex.com.
 *
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 ****/

#include "stdafx.h"

#include <CoreFoundation/CoreFoundation.h>
#include <CFNetwork/CFNetwork.h>
#include <SystemConfiguration/SCDynamicStoreCopySpecific.h>

#if defined(BOOST_NO_CXX11_SMART_PTR)
#error "Cpp rest SDK requires c++11 smart pointer support from boost"
#endif

#include "cpprest/details/http_client_impl.h"
#include <unordered_set>

using boost::asio::ip::tcp;
using namespace concurrency::streams;

namespace web { namespace http
	{
		namespace client
		{
			namespace details
			{
				class apple_client : public _http_client_communicator, public std::enable_shared_from_this<apple_client>
				{
				public:
					apple_client(http::uri address, http_client_config client_config)
					: _http_client_communicator(std::move(address), client_config)
					{}
					
					void send_request(const std::shared_ptr<request_context> &request_ctx) override;
					
					unsigned long open() override { return 0; }
				};
				
				class asio_context : public request_context, public std::enable_shared_from_this<asio_context>
				{
					friend class apple_client;
					
				private:
					
					template <class T> class corefoundation_ptr {
					public:
						corefoundation_ptr(const std::shared_ptr<T>& context) :m_retainCount(0), m_context(context) {
						
						}
						
						static void *retain(void *handler)
						{
							corefoundation_ptr *concreteHandler = static_cast<corefoundation_ptr *>(handler);
							concreteHandler->retain();
							return handler;
						}
						
						static void release(void *handler)
						{
							corefoundation_ptr *concreteHandler = static_cast<corefoundation_ptr *>(handler);
							
							if (concreteHandler->release() == 0) {
								delete concreteHandler;
							}
						}
						
						static const void *retain(const void *handler)
						{
							return retain((void *)handler);
						}
						
						static void release(const void *handler)
						{
							release((void *)handler);
						}
						
						void retain()
						{
							m_retainCount++;
						}
						
						int release()
						{
							return --m_retainCount;
						}
						
						std::shared_ptr<T> get()
						{
							return m_context;
						}
						
					private:
						std::atomic_int m_retainCount;
						std::shared_ptr<T> m_context;
					};
					
					static void writeRequestStreamEventCallback(CFWriteStreamRef stream, CFStreamEventType eventType, void *clientCallBackInfo)
					{
						corefoundation_ptr<asio_context> *context = (corefoundation_ptr<asio_context> *)clientCallBackInfo;
						context->get()->handle_write_request_event(eventType);
					}
					
					static void httpStreamEventCallback(CFReadStreamRef stream, CFStreamEventType eventType, void *clientCallBackInfo)
					{
						corefoundation_ptr<asio_context> *context = (corefoundation_ptr<asio_context> *)clientCallBackInfo;
						context->get()->handle_http_event(stream, eventType);
					}
					
					static void timeoutTimerEventCallback(CFRunLoopTimerRef timer, void *clientCallBackInfo)
					{
						corefoundation_ptr<asio_context> *context = (corefoundation_ptr<asio_context> *)clientCallBackInfo;
						context->get()->handle_timer_event();
					}
					
					static void read_all_headers(const void *key, const void *value, void *context)
					{
						http_headers *headers = static_cast<http_headers *>(context);
						CFStringRef keyCF = static_cast<CFStringRef>(key);
						CFStringRef valueCF = static_cast<CFStringRef>(value);
						
						std::string keySTD = copy_cfstringref_to_std_string(keyCF, kCFStringEncodingUTF8);
						std::string valueSTD = copy_cfstringref_to_std_string(valueCF, kCFStringEncodingUTF8);
						
						headers->add(keySTD, valueSTD);
					}
					
					static std::string copy_cfstringref_to_std_string(CFStringRef aString, CFStringEncoding encoding) {
						if (aString == NULL) {
							return NULL;
						}
						
						std::string result;
						
						CFIndex length = CFStringGetLength(aString);
						CFIndex maxSize =
						CFStringGetMaximumSizeForEncoding(length,
														  encoding);
						char *buffer = (char *)malloc(maxSize);
						if (CFStringGetCString(aString, buffer, maxSize,
											   encoding)) {
							result = std::string(buffer);
						}
						
						delete [] buffer;
						
						return result;
					}
					
				public:
					asio_context(const std::shared_ptr<_http_client_communicator> &client,
								 http_request &request)
					: request_context(client, request)
					, m_request_body_stream_writer(NULL)
					, m_request_body_stream_reader(NULL)
					, m_http_stream(NULL)
					, m_timeout_timer(NULL)
					, m_chunked_request(false)
					, m_timed_out(false)
					, m_has_response_headers(false)
					, m_need_proxy_auth(false)
					, m_content_length_request(0)
					{
						
					}
					
					virtual ~asio_context()
					{
						if(m_timeout_timer) {
							CFRelease(m_timeout_timer);
						}
					}
					
					static std::shared_ptr<request_context> create_request_context(std::shared_ptr<_http_client_communicator> &client, http_request &request)
					{
						auto client_cast(std::static_pointer_cast<apple_client>(client));
						auto ctx = std::make_shared<asio_context>(client, request);
						return ctx;
					}
					
					void start_request()
					{
						m_need_proxy_auth = false;
						if (m_request._cancellation_token().is_canceled())
						{
							request_context::report_error(make_error_code(std::errc::operation_canceled).value(), "Request canceled by user.");
							return;
						}
						
						const auto &base_uri = m_http_client->base_uri();
						auto encoded_resource = uri_builder(base_uri).append(m_request.relative_uri()).to_string();
						
						const auto &method = m_request.method();
						
						// stop injection of headers via method
						// resource should be ok, since it's been encoded
						// and host won't resolve
						if (!::web::http::details::validate_method(method))
						{
							report_exception(http_exception("The method string is invalid."));
							return;
						}
						
						if(m_request.body()) {
							
							// Check user specified transfer-encoding.
							std::string transferencoding;
							if (m_request.headers().match(header_names::transfer_encoding, transferencoding) && transferencoding == "chunked")
							{
								m_chunked_request = true;
							}
							else if (!m_request.headers().match(header_names::content_length, m_content_length_request))
							{
								// Stream without content length is the signal of requiring transfer encoding chunked.
								m_chunked_request = true;
							}
						} else {
							update_upload_progress_handler();
						}
						
						//TODO ALL
						
						CFStringRef url = CFStringCreateWithCString(kCFAllocatorDefault, encoded_resource.c_str(), kCFStringEncodingUTF8);
						CFURLRef myURL = CFURLCreateWithString(kCFAllocatorDefault, url, NULL);
						CFStringRef requestMethod = CFStringCreateWithCString(kCFAllocatorDefault, method.c_str(), kCFStringEncodingUTF8);
						
						CFHTTPMessageRef httpMessage = CFHTTPMessageCreateRequest(kCFAllocatorDefault,
																				  requestMethod, myURL, kCFHTTPVersion1_1);
						auto headers = m_request.headers();
						std::vector<CFStringRef> headerStringsToRelease;
						for(auto iter = headers.begin(); iter != headers.end(); ++iter)
						{
							utility::string_t headerField = (*iter).first;
							utility::string_t headerValue = (*iter).second;
							CFStringRef headerFieldCF = CFStringCreateWithCString(kCFAllocatorDefault, headerField.c_str(), kCFStringEncodingUTF8);
							CFStringRef headerValueCF = CFStringCreateWithCString(kCFAllocatorDefault, headerValue.c_str(), kCFStringEncodingUTF8);
							
							headerStringsToRelease.push_back(headerFieldCF);
							headerStringsToRelease.push_back(headerValueCF);
							
							CFHTTPMessageSetHeaderFieldValue(httpMessage, headerFieldCF, headerValueCF);
						}
						
						size_t bufferSize = m_http_client->client_config().chunksize() * 3;
						
						CFStreamCreateBoundPair(kCFAllocatorDefault, &m_request_body_stream_reader, &m_request_body_stream_writer, bufferSize);
						
						if(m_chunked_request) {
							m_http_stream = CFReadStreamCreateForStreamedHTTPRequest(kCFAllocatorDefault, httpMessage, m_request_body_stream_reader);
						} else {
							if (m_request.body()) {
								__block int totalWasRead = 0;
								__block int wasRead = 0;
								__block std::string lines;
								do {
									read_request_body_and(^(int readSize, const std::string &line) {
										wasRead = readSize;
										if (readSize) {
											lines += line;
										}
									});
								} while(wasRead);
								
								CFHTTPMessageSetBody(httpMessage, CFDataCreate(kCFAllocatorDefault, (UInt8 *)lines.c_str(), lines.size()));
							}
							m_http_stream = CFReadStreamCreateForHTTPRequest(kCFAllocatorDefault, httpMessage);
						}
						
						CFReadStreamSetProperty(m_http_stream,
												kCFStreamPropertyHTTPShouldAutoredirect,
												kCFBooleanTrue);
						
						if (m_http_client->client_config().validate_certificates() == false) {
							
							CFMutableDictionaryRef sslSettings = CFDictionaryCreateMutable(kCFAllocatorDefault, 3, NULL, NULL);
							CFDictionaryAddValue(sslSettings, kCFStreamSSLAllowsExpiredCertificates, kCFBooleanTrue);
						 	CFDictionaryAddValue(sslSettings, kCFStreamSSLAllowsAnyRoot, kCFBooleanTrue);
							CFDictionaryAddValue(sslSettings, kCFStreamSSLValidatesCertificateChain, kCFBooleanFalse);
							
							CFReadStreamSetProperty(m_http_stream,
													kCFStreamPropertySSLSettings,
													(CFTypeRef)sslSettings);
							CFRelease(sslSettings);
						}
						
						CFDictionaryRef proxySettings = NULL;
						
						web_proxy wproxy = m_http_client->client_config().proxy();
						if (wproxy.is_disabled() == false && wproxy.is_specified()) {
							CFMutableDictionaryRef mutableProxySetting = CFDictionaryCreateMutable(kCFAllocatorDefault, 2, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
							uri address_uri = wproxy.address();
							std::string adress_s = address_uri.host();
							CFStringRef address_cfs = CFStringCreateWithCString(kCFAllocatorDefault, adress_s.c_str(), kCFStringEncodingUTF8);
							int port_int = address_uri.port();
							CFNumberRef port_cfn = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &port_int);
							
							CFDictionaryAddValue(mutableProxySetting, kCFStreamPropertyHTTPProxyHost, address_cfs);
							CFDictionaryAddValue(mutableProxySetting, kCFStreamPropertyHTTPProxyPort, port_cfn);
							CFDictionaryAddValue(mutableProxySetting, kCFStreamPropertyHTTPSProxyHost, address_cfs);
							CFDictionaryAddValue(mutableProxySetting, kCFStreamPropertyHTTPSProxyPort, port_cfn);
							
							CFRelease(port_cfn); port_cfn = NULL;
							CFRelease(address_cfs); address_cfs = NULL;
							proxySettings = mutableProxySetting;
						} else if(wproxy.is_disabled() == false && wproxy.is_default()) {
							proxySettings = SCDynamicStoreCopyProxies(NULL);
						}
						
						if (proxySettings) {
							CFReadStreamSetProperty(m_http_stream, kCFStreamPropertyHTTPProxy, proxySettings);
							CFRelease(proxySettings);
							proxySettings = NULL;
						}
						
						CFRelease(httpMessage); httpMessage = NULL;
						CFRelease(url); url = NULL;
						CFRelease(myURL); myURL = NULL;
						CFRelease(requestMethod); requestMethod = NULL;
						for(auto iter = headerStringsToRelease.begin(); iter != headerStringsToRelease.end(); ++iter)
						{
							CFStringRef headerStringToRelease = (*iter);
							CFRelease(headerStringToRelease);
						}
						
						start_timer();
						
						corefoundation_ptr<asio_context> *context_ptr = new corefoundation_ptr<asio_context>(shared_from_this());
						CFStreamClientContext streamContext =
						{ 0, context_ptr, corefoundation_ptr<asio_context>::retain, corefoundation_ptr<asio_context>::release, NULL };
						if (CFReadStreamSetClient(m_http_stream,
												  kCFStreamEventOpenCompleted | kCFStreamEventHasBytesAvailable | kCFStreamEventErrorOccurred | kCFStreamEventEndEncountered,
												  httpStreamEventCallback,
												  &streamContext))
						{
							CFReadStreamScheduleWithRunLoop(m_http_stream, CFRunLoopGetCurrent(), kCFRunLoopCommonModes);
							
							if (!CFReadStreamOpen(m_http_stream)) {
								CFStreamError myErr = CFReadStreamGetError(m_http_stream);
								
								request_context::report_error(myErr.error, "Error while opening request stream to start it");
								return;
							} else {
								CFRunLoopRun();
							}
						}
					}
					
					template<typename _ExceptionType>
					void report_exception(const _ExceptionType &e)
					{
						report_exception(std::make_exception_ptr(e));
					}
					
					void report_exception(std::exception_ptr exceptionPtr) override
					{
						request_context::report_exception(exceptionPtr);
						end();
					}
					
				private:
					void read_request_body_and(void(^andHandler)(int, const std::string &)) {
						
						bool is_exception = false;
						
						istream requestBodyIStream = m_request.body();
						// Read a line from the stream into a string.
						container_buffer<std::string> inStringBuffer;
						const auto this_request = this;
						int readSize;
						
						auto afterBodyRead = [this_request, &readSize, &is_exception](pplx::task<size_t> op)
						{
							try
							{
								readSize = op.get();
							}
							catch (...)
							{
								this_request->report_exception(std::current_exception());
								is_exception = true;
							}
						};
						
						auto sizeToRead = m_http_client->client_config().chunksize();
						if(m_content_length_request) {
							sizeToRead = static_cast<size_t>(std::min(static_cast<uint64_t>(m_http_client->client_config().chunksize()),
																	  m_content_length_request - m_uploaded));
						}
						requestBodyIStream.read(inStringBuffer, sizeToRead).then(afterBodyRead).wait();
						
						reset_timer();
						
						if(is_exception == false) {
							const std::string &line = inStringBuffer.collection();
							reset_timer();
							m_uploaded += static_cast<uint64_t>(readSize);
							update_upload_progress_handler();
							andHandler(readSize, line);
						}
					}
					
					void download_content_and_continue()
					{
						if(!m_http_stream){
							return;
						}
						
						std::string receiving_buffer;
						receiving_buffer.resize(m_http_client->client_config().chunksize());
						CFIndex readSize = 0;
						try {
							readSize = CFReadStreamRead(m_http_stream, (UInt8 *)receiving_buffer.c_str(), m_http_client->client_config().chunksize());
							
							container_buffer<std::string> outStringBuffer(std::move(receiving_buffer));
							ostream response_output_stream = m_response._get_impl()->outstream();
							response_output_stream.write(outStringBuffer, readSize).then([](size_t bytesWritten) {
							}).wait();
							
							reset_timer();
							
							m_downloaded += static_cast<uint64_t>(readSize);
							update_download_progress_handler();
							
						} catch(...) {
							if(readSize) {
								CFStreamError error = CFReadStreamGetError(m_http_stream);
								report_exception(http_exception(error.error));
							} else {
								report_exception(std::current_exception());
							}
						}
						
					}
					
					void update_upload_progress_handler()
					{
						const auto &progress = m_request._get_impl()->_progress_handler();
						if (progress)
						{
							try
							{
								(*progress)(message_direction::upload, m_uploaded);
							}
							catch(...)
							{
								report_exception(std::current_exception());
								return;
							}
						}
					}
					
					void update_download_progress_handler()
					{
						
						const auto &progress = m_request._get_impl()->_progress_handler();
						if (progress)
						{
							try
							{
								(*progress)(message_direction::download, m_downloaded);
							}
							catch(...)
							{
								report_exception(std::current_exception());
								return;
							}
						}
					}
					
					void download_headers_if_do_not_have()
					{
						if (!m_http_stream) {
							return;
						}
						
						CFHTTPMessageRef myResponse = (CFHTTPMessageRef)CFReadStreamCopyProperty(m_http_stream, kCFStreamPropertyHTTPResponseHeader);
						if(myResponse) {
							if (m_has_response_headers == false) {
								CFStringRef myStatusLine = CFHTTPMessageCopyResponseStatusLine(myResponse);
								CFIndex myStatusCode = CFHTTPMessageGetResponseStatusCode(myResponse);
								CFRelease(myResponse);
								
								std::string reasonPhrase = copy_cfstringref_to_std_string(myStatusLine, kCFStringEncodingUTF8);
								CFRelease(myStatusLine);
								m_response.set_status_code((short)myStatusCode);
								
								std::stringstream sstream(reasonPhrase);
								std::istream_iterator<std::string> begin(sstream);
								std::istream_iterator<std::string> end;
								std::vector<std::string> vstrings(begin, end);
								
								if (vstrings.size() > 2) {
									m_response.set_reason_phrase(vstrings[2]);
								}
								
								CFDictionaryRef headers = CFHTTPMessageCopyAllHeaderFields(myResponse);
								CFDictionaryApplyFunction(headers, read_all_headers, &m_response.headers());
								CFRelease(headers);
								
								
								m_has_response_headers = true;
								if (myStatusCode == 407) {
									m_need_proxy_auth = true;
									return;
								}
								
								complete_headers();
							}
						}
					}
					
					void tryWriting()
					{
						if (!m_request_body_stream_reader) {
							return;
						}
						
						if (CFReadStreamGetStatus(m_request_body_stream_reader) == kCFStreamStatusOpen) {
							
							corefoundation_ptr<asio_context> *context_ptr = new corefoundation_ptr<asio_context>(shared_from_this());
							CFStreamClientContext streamContext =
								{ 0, context_ptr, corefoundation_ptr<asio_context>::retain, corefoundation_ptr<asio_context>::release, NULL };
							if (CFWriteStreamSetClient(m_request_body_stream_writer,
													  kCFStreamEventOpenCompleted | kCFStreamEventCanAcceptBytes | kCFStreamEventErrorOccurred | kCFStreamEventEndEncountered,
													  writeRequestStreamEventCallback,
													  &streamContext))
							{
								CFWriteStreamScheduleWithRunLoop(m_request_body_stream_writer, CFRunLoopGetCurrent(), kCFRunLoopCommonModes);
								if (!CFWriteStreamOpen(m_request_body_stream_writer)) {
									CFStreamError myErr = CFWriteStreamGetError(m_request_body_stream_writer);
									
									request_context::report_error(myErr.error, "Error while opening request stream to start it");
									return;
								}
							}
							
						} else {
							CFRunLoopPerformBlock(CFRunLoopGetCurrent(), kCFRunLoopCommonModes, ^{
								tryWriting();
							});
						}
						
					}
					
					void handle_write_request_event(CFStreamEventType eventType)
					{
						switch(eventType) {
							case kCFStreamEventOpenCompleted:
							{
								
							}
								
							case kCFStreamEventCanAcceptBytes:
							{
								if (m_chunked_request) {
									read_request_body_and(^(int readSize, const std::string &line){
										if(readSize > 0) {
											CFWriteStreamWrite(m_request_body_stream_writer, (UInt8 *)line.c_str(), readSize);
										} else {
											if (m_request_body_stream_writer) {
												CFWriteStreamClose(m_request_body_stream_writer);
											}
										}
									});
								}
								break;
							}
							case kCFStreamEventErrorOccurred:
							{
								
								break;
							}
							case kCFStreamEventEndEncountered:
							{
								
								break;
							}
						}
					}
					
					void handle_http_event(CFReadStreamRef stream, CFStreamEventType eventType)
					{
						reset_timer();
						
						switch(eventType) {
							case kCFStreamEventOpenCompleted:
							{
								if(m_chunked_request) {
									tryWriting();
								}
								break;
							}
							
							case kCFStreamEventHasBytesAvailable:
							{
								if (m_http_stream) {
									download_content_and_continue();
									download_headers_if_do_not_have();
								}
								
								break;
							}
							case kCFStreamEventErrorOccurred:
							{
								int casablancaErrorCode = 0;
								std::string reasonSTD = "Unknown reason";
								
								CFErrorRef error = CFReadStreamCopyError(m_http_stream);
								if (error) {
									CFStringRef domain = CFErrorGetDomain(error);
									CFIndex code = CFErrorGetCode(error);
									CFStringRef reason = CFErrorCopyFailureReason(error);
									std::string reasonSTD;
									
									if (reason) {
										reasonSTD = copy_cfstringref_to_std_string(reason, kCFStringEncodingUTF8);
										CFRelease(reason);
									}
									
									if (domain == kCFErrorDomainPOSIX) {
										if (code == ECONNREFUSED) {
											casablancaErrorCode = make_error_code(std::errc::host_unreachable).value();
										}
										
									} else if(domain == kCFErrorDomainCFNetwork) {
										if(code == kCFURLErrorNetworkConnectionLost) {
											casablancaErrorCode = make_error_code(std::errc::connection_aborted).value();
										}
									} else {
										casablancaErrorCode = code;
									}
									
								}
								
								report_error(casablancaErrorCode, reasonSTD);
								
								CFRelease(error);
								
								break;
							}
							case kCFStreamEventEndEncountered:
							{
								if (m_http_stream) {
									download_content_and_continue();
									download_headers_if_do_not_have();
								}
								end();
								
								if(m_need_proxy_auth) {
									start_request();
								} else {
									complete_request(m_downloaded);
								}
								
								break;
							}
						}
					}
					
					void handle_timer_event()
					{
						m_timed_out = true;
						int timeoutErrorCode = make_error_code(std::errc::timed_out).value();
						if (m_request.body() && m_request.body().is_open()) {
							m_request.body().close(std::make_exception_ptr(http_exception(static_cast<int>(timeoutErrorCode))));
						}
						
						report_error(timeoutErrorCode, "Request timedout.");
					}
					
					void end()
					{
						stop_timer();
						if (m_http_stream) {
							CFReadStreamClose(m_http_stream);
							
							CFReadStreamUnscheduleFromRunLoop(m_http_stream, CFRunLoopGetCurrent(),
															  kCFRunLoopCommonModes);
							CFRelease(m_http_stream);
							m_http_stream = NULL;
							
						}
						
						if (m_request_body_stream_reader) {
							CFReadStreamClose(m_request_body_stream_reader);
							CFRelease(m_request_body_stream_reader);
							m_request_body_stream_reader = NULL;
						}
						
						if (m_request_body_stream_writer) {
							CFWriteStreamUnscheduleFromRunLoop(m_request_body_stream_writer, CFRunLoopGetCurrent(),
															  kCFRunLoopCommonModes);
							CFWriteStreamClose(m_request_body_stream_writer);
							CFRelease(m_request_body_stream_writer);
							m_request_body_stream_writer = NULL;
						}
					}
					
					void start_timer()
					{
						corefoundation_ptr<asio_context> *context_ptr = new corefoundation_ptr<asio_context>(shared_from_this());
						CFRunLoopTimerContext timerContext =
						{ 0, context_ptr, corefoundation_ptr<asio_context>::retain, corefoundation_ptr<asio_context>::release, NULL };
						m_timeout_timer =
							CFRunLoopTimerCreate(
											 kCFAllocatorDefault,
											 CFAbsoluteTimeGetCurrent() + static_cast<int>(m_http_client->client_config().timeout().count()),
											 0,
											 0,
											 0,
											 timeoutTimerEventCallback,
											 &timerContext);
						CFRunLoopAddTimer(CFRunLoopGetCurrent(), m_timeout_timer, kCFRunLoopCommonModes);
					}
					
					void stop_timer()
					{
						if(m_timeout_timer) {
							CFRunLoopRemoveTimer(CFRunLoopGetCurrent(), m_timeout_timer, kCFRunLoopCommonModes);
							CFRelease(m_timeout_timer);
							m_timeout_timer = NULL;
						}
					}
					
					void reset_timer()
					{
						stop_timer();
						start_timer();
					}
					
					CFWriteStreamRef m_request_body_stream_writer;
					CFReadStreamRef m_request_body_stream_reader;
					CFReadStreamRef m_http_stream;
					CFRunLoopTimerRef m_timeout_timer;
					bool m_chunked_request;
					bool m_timed_out;
					bool m_has_response_headers;
					bool m_need_proxy_auth;
					uint64_t m_content_length_request;
				};
				
				http_network_handler::http_network_handler(const uri &base_uri, const http_client_config &client_config) :
					m_http_client_impl(std::make_shared<apple_client>(base_uri, client_config))
				{}
				
				pplx::task<http_response> http_network_handler::propagate(http_request request)
				{
					auto context = details::asio_context::create_request_context(m_http_client_impl, request);
					
					// Use a task to externally signal the final result and completion of the task.
					auto result_task = pplx::create_task(context->m_request_completion);
					
					// Asynchronously send the response with the HTTP client implementation.
					m_http_client_impl->async_send_request(context);
					
					return result_task;
				}
				
				void apple_client::send_request(const std::shared_ptr<request_context> &request_ctx)
				{
					CFStringRef bodyString = CFSTR("");
					
					auto ctx = std::static_pointer_cast<asio_context>(request_ctx);
					
					try
					{
						//Invoke upon some resource
						//client_config().invoke_nativehandle_options(&(ctx->m_connection->m_socket));
					}
					catch (...)
					{
						request_ctx->report_exception(std::current_exception());
						return;
					}
					
					ctx->start_request();
				}
				
			}}}} // namespaces
