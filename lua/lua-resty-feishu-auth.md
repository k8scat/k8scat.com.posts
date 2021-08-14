# 飞书 + Lua 实现企业级组织架构登录认证

![](https://pic3.zhimg.com/v2-6f1ed5de3e7587b848024b63c40e2ba5_r.jpg)

飞书是字节跳动旗下一款企业级协同办公软件，本文将介绍如何基于飞书开放平台的身份验证能力，使用 Lua 实现企业级组织架构的登录认证网关。

## 登录流程

让我们首先看一下飞书第三方网站免登的整体流程：

第一步: 网页后端发现用户未登录，请求身份验证；
第二步: 用户登录后，开放平台生成登录预授权码，302跳转至重定向地址；
第三步: 网页后端调用获取登录用户身份校验登录预授权码合法性，获取到用户身份；
第四步: 如需其他用户信息，网页后端可调用获取用户信息（身份验证）。

![浏览器内网页登录](https://sf3-cn.feishucdn.com/obj/website-img/faf8b877126e0a5bc7e76f7bc955c352_CCgGABCJpR.png)

## Lua 实现

### 飞书接口部分实现

#### 获取应用的 access_token

```lua
function _M:get_app_access_token()
    local url = "https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal/"
    local body = {
        app_id = self.app_id,
        app_secret = self.app_secret
    }
    local res, err = http_post(url, body, nil)
    if not res then
        return nil, err
    end
    if res.status ~= 200 then
        return nil, res.body
    end
    local data = json.decode(res.body)
    if data["code"] ~= 0 then
        return nil, res.body
    end
    return data["tenant_access_token"]
end
```

#### 通过回调 code 获取登录用户信息

```lua
function _M:get_login_user(code)
    local app_access_token, err = self:get_app_access_token()
    if not app_access_token then
        return nil, "get app_access_token failed: " .. err
    end
    local url = "https://open.feishu.cn/open-apis/authen/v1/access_token"
    local headers = {
        Authorization = "Bearer " .. app_access_token
    }
    local body = {
        grant_type = "authorization_code",
        code = code
    }
    ngx.log(ngx.ERR, json.encode(body))
    local res, err = http_post(url, body, headers)
    if not res then
        return nil, err
    end
    local data = json.decode(res.body)
    if data["code"] ~= 0 then
        return nil, res.body
    end
    return data["data"]
end
```

#### 获取用户详细信息

获取登录用户信息时无法获取到用户的部门信息，故这里需要使用登录用户信息中的 `open_id` 获取用户的详细信息，同时 `user_access_token` 也是来自于获取到的登录用户信息。

```lua
function _M:get_user(user_access_token, open_id)
    local url = "https://open.feishu.cn/open-apis/contact/v3/users/" .. open_id
    local headers = {
        Authorization = "Bearer " .. user_access_token
    }
    local res, err = http_get(url, nil, headers)
    if not res then
        return nil, err
    end
    local data = json.decode(res.body)
    if data["code"] ~= 0 then
        return nil, res.body
    end
    return data["data"]["user"], nil
end
```

### 登录信息

#### JWT 登录凭证

我们使用 JWT 作为登录凭证，同时用于保存用户的 `open_id` 和 `department_ids`。

```lua
-- 生成 token
function _M:sign_token(user)
    local open_id = user["open_id"]
    if not open_id or open_id == "" then
        return nil, "invalid open_id"
    end
    local department_ids = user["department_ids"]
    if not department_ids or type(department_ids) ~= "table" then
        return nil, "invalid department_ids"
    end

    return jwt:sign(
        self.jwt_secret,
        {
            header = {
                typ = "JWT",
                alg = jwt_header_alg,
                exp = ngx.time() + self.jwt_expire
            },
            payload = {
                open_id = open_id,
                department_ids = json.encode(department_ids)
            }
        }
    )
end

-- 验证与解析 token
function _M:verify_token()
    local token = ngx.var.cookie_feishu_auth_token
    if not token then
        return nil, "token not found"
    end

    local result = jwt:verify(self.jwt_secret, token)
    ngx.log(ngx.ERR, "jwt_obj: ", json.encode(result))
    if result["valid"] then
        local payload = result["payload"]
        if payload["department_ids"] and payload["open_id"] then
            return payload
        end
        return nil, "invalid token: " .. json.encode(result)
    end
    return nil, "invalid token: " .. json.encode(result)
end
```

#### 使用 Cookie 存储登录凭证

```lua
ngx.header["Set-Cookie"] = self.cookie_key .. "=" .. token
```

### 组织架构白名单

我们在用户登录时获取用户的部门信息，或者在用户后续访问应用时解析登录凭证中的部门信息，根据设置的部门白名单，判断用户是否拥有访问应用的权限。

```lua
-- 部门白名单配置
_M.department_whitelist = {}

function _M:check_user_access(user)
    if type(self.department_whitelist) ~= "table" then
        ngx.log(ngx.ERR, "department_whitelist is not a table")
        return false
    end
    if #self.department_whitelist == 0 then
        return true
    end

    local department_ids = user["department_ids"]
    if not department_ids or department_ids == "" then
        return false
    end
    if type(department_ids) ~= "table" then
        department_ids = json.decode(department_ids)
    end
    for i=1, #department_ids do
        if has_value(self.department_whitelist, department_ids[i]) then
            return true
        end
    end
    return false
end
```

### 更多网关配置

同时支持 IP 黑名单和路由白名单配置。

```lua
-- IP 黑名单配置
_M.ip_blacklist = {}
-- 路由白名单配置
_M.uri_whitelist = {}

function _M:auth()
    local request_uri = ngx.var.uri
    ngx.log(ngx.ERR, "request uri: ", request_uri)

    if has_value(self.uri_whitelist, request_uri) then
        ngx.log(ngx.ERR, "uri in whitelist: ", request_uri)
        return
    end

    local request_ip = ngx.var.remote_addr
    if has_value(self.ip_blacklist, request_ip) then
        ngx.log(ngx.ERR, "forbided ip: ", request_ip)
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end

    if request_uri == self.logout_uri then
        return self:logout()
    end

    local payload, err = self:verify_token()
    if payload then
        if self:check_user_access(payload) then
            return
        end

        ngx.log(ngx.ERR, "user access not permitted")
        self:clear_token()
        return self:sso()
    end
    ngx.log(ngx.ERR, "verify token failed: ", err)

    if request_uri ~= self.callback_uri then
        return self:sso()
    end
    return self:sso_callback()
end
```

## 使用

本文就不赘述 OpenResty 的安装了，可以参考我的另一篇文章[《在 Ubuntu 上使用源码安装 OpenResty》](https://k8scat.com/posts/linux/install-openresty-on-ubuntu-from-source-code/)。

### 下载

```bash
cd /path/to
git clone git@github.com:ledgetech/lua-resty-http.git
git clone git@github.com:SkyLothar/lua-resty-jwt.git
git clone git@github.com:k8scat/lua-resty-feishu-auth.git
```

### 配置

```conf
lua_package_path "/path/to/lua-resty-feishu-auth/lib/?.lua;/path/to/lua-resty-jwt/lib/?.lua;/path/to/lua-resty-http/lib/?.lua;/path/to/lua-resty-redis/lib/?.lua;/path/to/lua-resty-redis-lock/lib/?.lua;;";

server {
    access_by_lua_block {
        local feishu_auth = require "resty.feishu_auth"
        feishu_auth.app_id = ""
        feishu_auth.app_secret = ""
        feishu_auth.callback_uri = "/feishu_auth_callback"
        feishu_auth.logout_uri = "/feishu_auth_logout"
        feishu_auth.app_domain = "feishu-auth.example.com"

        feishu_auth.jwt_secret = "thisisjwtsecret"

        feishu_auth.ip_blacklist = {"47.1.2.3"}
        feishu_auth.uri_whitelist = {"/"}
        feishu_auth.department_whitelist = {"0"}

        feishu_auth:auth()
    }
}
```

### 配置说明

- `app_id` 用于设置飞书企业自建应用的 `App ID`
- `app_secret` 用于设置飞书企业自建应用的 `App Secret`
- `callback_uri` 用于设置飞书网页登录后的回调地址（需在飞书企业自建应用的安全设置中设置重定向 URL）
- `logout_uri` 用于设置登出地址
- `app_domain` 用于设置访问域名（需和业务服务的访问域名一致）
- `jwt_secret` 用于设置 JWT secret
- `ip_blacklist` 用于设置 IP 黑名单
- `uri_whitelist` 用于设置地址白名单，例如首页不需要登录认证
- `department_whitelist` 用于设置部门白名单（字符串）

### 应用权限说明

- 获取部门基础信息
- 获取部门组织架构信息
- 以应用身份读取通讯录
- 获取用户组织架构信息
- 获取用户基本信息

## 开源

本项目已完成且已在 GitHub 上开源：[k8scat/lua-resty-feishu-auth](https://github.com/k8scat/lua-resty-feishu-auth)，希望大家可以动动手指点个 Star，表示对本项目的肯定与支持！
