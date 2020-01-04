/*! @file
**********************************************************************
<PRE>
模块名       : 
文件名       : HttpRequest.h
相关文件     : HttpRequest.cpp
文件实现功能 : Http 请求
作者         : Song
版本         : 1.0
----------------------------------------------------------------------
备注         : 
----------------------------------------------------------------------
修改记录     : 
日 期        版本   修改人                 修改内容 
2018/4/10    1.0    Song                    创建
</PRE>
**********************************************************************

* 版权所有(c) 2018-2019, 保留所有权利

*********************************************************************/
#pragma once
#include <string>
#include <vector>

class HttpRequest
{
public:
    HttpRequest(const std::string& ip, int port);
    ~HttpRequest(void);

    // Http GET请求
    std::string HttpGet(std::string req);

    // Http POST请求
    std::string HttpPost(std::string req, std::string data);

    // 合成JSON字符串
    //static std::string genJsonString(std::string key, int value);

    // 分割字符串
    static std::vector<std::string> split(const std::string &s, const std::string &seperator);

	// 根据key从Response获取Body中的内容
	static std::string getBody(std::string respose);

    // 根据key从Response获取Header中的内容
    static std::string getHeader(std::string respose, std::string key);

private:
    std::string         m_ip;
    int             m_port;
};
