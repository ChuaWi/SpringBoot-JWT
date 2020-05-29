# SpringBoot集成JWT实现token验证
**JWT**，英文全称**JSON Web Token**：JSON网络令牌。为了在网络应用环境间传递声明而制定的一种基于JSON的开放标准(RFC 7519)。这个规范允许我们使用JWT在客户端和服务端之间传递安全可靠的信息。
JWT是一个轻便的安全跨平台传输格式，定义了一个<code>**紧凑自包含**</code>的方式，用于通信双方之间作为 JSON 对象安全地传递信息。此信息可以通过数字签名进行验证和信任。

>  - 紧凑：这个字符串简洁，数据量小，传输速度快，能通过URL参数、HTTP请求提交的数据以及HTTP Header的方式进行传递。
>  - 自包含：负载中包含很多信息，比如用户的ID等。别人拿到这个字符串，就能拿到这些关键的业务信息，从而避免再通过数据库查询等方式得到它们。

**JWT的结构**
JWT由三段信息用.连接构成的字符串。

**<code>Header</code>.<code>Payload</code>.<code>Signature</code>**
例如：
<table><tr><td bgcolor=#D1EEEE><font color=blue>eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiIxIn0.ihOZFzg3ZGIbBMneRy-4RMqors1P3nuO-wRJnQtTzWQ</font></td></tr></table>

 - **<code>Header</code>头部**

承载两部分信息：token类型和采用的加密算法

```java
{ 
  "typ": "JWT",
  "alg": "HS256"
}
```
token类型：JWT
加密算法：HS256

 - **<code>Payload</code>负载**

存放有效信息的地方

> iss: jwt签发者 
> sub: jwt所面向的用户
> aud: 接收jwt的一方 
> exp: 过期时间戳(jwt的过期时间，这个过期时间必须要大于签发时间) 
> nbf: 定义在什么时间之前，该jwt都是不可用的
> iat: jwt的签发时间
> jti: jwt的唯一身份标识，主要用来作为一次性token，从而回避重放攻击

 - **<code>Signature</code>签名**

对头部及负载内容进行签证。采用Header中声明的算法，接收三个参数：base64编码的Header、base64编码的Payload和密钥（secret）进行运算。密钥secret是保存在服务端的，服务端会根据这个密钥进行生成token和进行验证。

**JWT的工作流程**
![在这里插入图片描述](https://img-blog.csdnimg.cn/2020052615572243.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NDMxNjUyNw==,size_16,color_FFFFFF,t_70#pic_center)

>  如上图所示：
>      1. 输入用户名和密码，进行登录
>      2. 服务器对登录用户进行认证（如果认证通过，根据用户的信息和JWT的生成规则生成token）
>      3. 服务器将该token字符串返回给用户
>      4. 当用户请求服务器API时，在请求的Header中加入token
>      5. 服务端进行校验（如果通过，则解析其中内容，根据其权限和业务逻辑给出响应结果。如果不通过，返回401）
>      6. 返回请求数据

<font size=5>**SpringBoot集成JWT实现token验证步骤**</font>

 **1. 引入JWT依赖**
```java
<dependency>
    <groupId>com.auth0</groupId>
    <artifactId>java-jwt</artifactId>
    <version>3.4.0</version>
</dependency>
```
 **2. 自定义实体User类**
```java
@Data
@AllArgsConstructor
@NoArgsConstructor
public class User {
    String Id;
    String username;
    String password;
}
```
 **3. 生成token方法**
```java
@Service("TokenService")
public class TokenService {
    public String getToken(User user) {
        String token="";
        // 存入需要保存在token里的信息，这里把用户ID存入token
        token= JWT.create().withAudience(user.getId())
                .sign(Algorithm.HMAC256(user.getPassword()));
        // 使用HMAC256加密算法生成token,密钥是用户的密码
        return token;
    }
}
```
 **4. 拦截器获取并验证token**
```java
public class AuthenticationInterceptor implements HandlerInterceptor {
    @Autowired
    UserService userService;
    @Override
    public boolean preHandle(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Object object) throws Exception {
        // 从 http 请求头中取出 token
        String token = httpServletRequest.getHeader("token");
        // 如果不是映射到方法直接通过
        if(!(object instanceof HandlerMethod)){
            return true;
        }
        HandlerMethod handlerMethod=(HandlerMethod)object;
        Method method=handlerMethod.getMethod();
        // 检查是否有passtoken注释，有则跳过认证
        if (method.isAnnotationPresent(PassToken.class)) {
            PassToken passToken = method.getAnnotation(PassToken.class);
            if (passToken.required()) {
                return true;
            }
        }
        // 检查有没有需要用户权限的注解
        if (method.isAnnotationPresent(UserLoginToken.class)) {
            UserLoginToken userLoginToken = method.getAnnotation(UserLoginToken.class);
            if (userLoginToken.required()) {
                // 执行认证
                if (token == null) {
                    throw new RuntimeException("无token，请重新登录");
                }
                // 获取 token 中的 userId
                String userId;
                try {
                    userId = JWT.decode(token).getAudience().get(0);
                } catch (JWTDecodeException j) {
                    throw new RuntimeException("401");
                }
                User user = userService.findUserById(userId);
                if (user == null) {
                    throw new RuntimeException("用户不存在，请重新登录");
                }
                // 验证 token
                JWTVerifier jwtVerifier = JWT.require(Algorithm.HMAC256(user.getPassword())).build();
                try {
                    jwtVerifier.verify(token);
                } catch (JWTVerificationException e) {
                    throw new RuntimeException("401");
                }
                return true;
            }
        }
        return true;
    }

    @Override
    public void postHandle(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Object o, ModelAndView modelAndView) throws Exception {

    }
    @Override
    public void afterCompletion(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Object o, Exception e) throws Exception {

    }
}
```
<code>boolean preHandle()</code>预处理回调方法,实现处理器的预处理，第三个参数为响应的处理器，自定义Controller
返回值为true表示继续流程（如调用下一个拦截器或处理器）或者接着执行postHandle()和afterCompletion()
返回值为false表示流程中断，不会继续调用其他的拦截器或处理器，中断执行

 **5. 配置拦截器**
 在配置类上添加了注解<code>@Configuration</code>，标明了该类是一个配置类并且会将该类作为一个SpringBean添加到IOC容器内
```java
@Configuration
public class InterceptorConfig implements WebMvcConfigurer {
    @Override
    //addPathPatterns方法用于设置拦截器的过滤路径规则
    public void addInterceptors(InterceptorRegistry registry) {
        // 拦截所有请求，通过判断是否有 @LoginRequired 注解 决定是否需要登录
        registry.addInterceptor(authenticationInterceptor())
                .addPathPatterns("/**");
    }
    @Bean
    public AuthenticationInterceptor authenticationInterceptor() {
        return new AuthenticationInterceptor();
    }
}
```
 **6. 数据访问接口**
```java
@RestController
@RequestMapping("api")
public class UserApi {
    @Autowired
    UserService userService;
    @Autowired
    TokenService tokenService;
    //登录
    @PostMapping("/login")
    public Object login( User user){
        JSONObject jsonObject=new JSONObject();
        User userForBase=userService.findByUsername(user);
        if(userForBase==null){
            jsonObject.put("message","登录失败,用户不存在");
            return jsonObject;
        }else {
            if (!userForBase.getPassword().equals(user.getPassword())){
                jsonObject.put("message","登录失败,密码错误");
                return jsonObject;
            }else {
                String token = tokenService.getToken(userForBase);
                jsonObject.put("token", token);
                jsonObject.put("user", userForBase);
                return jsonObject;
            }
        }
    }
    
    @UserLoginToken
    @GetMapping("/getMessage")
    //登录注解，说明该接口必须登录获取token后，在请求头中加上token并通过验证才可以访问
    public String getMessage(){
        return "你已通过验证";
    }
}
```
**下面（根据JWT工作流程）进行测试，启动项目，使用[点击这里下载>postman](https://www.postman.com)测试接口**

1.在未使用账号密码和<code>token</code>登录的情况下，访问<font color=red>api/getMessage</font>接口

<font color=green>**GET**</font> http://localhost:8080/api/getMessage

![在这里插入图片描述](https://img-blog.csdnimg.cn/20200529165903803.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NDMxNjUyNw==,size_16,color_FFFFFF,t_70)

2.使用账号密码进行登录，访问<font color=red>api/login</font>接口，从而获取<code>token</code>

<font color=orange>**POST**</font> http://localhost:8080/api/login

![在这里插入图片描述](https://img-blog.csdnimg.cn/20200529165931878.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NDMxNjUyNw==,size_16,color_FFFFFF,t_70)

3.在请求头中加入token，再次访问<font color=red>api/getMessage</font>接口

<font color=green>**GET**</font> http://localhost:8080/api/getMessage

加上<code>**token**</code>之后就可以通过验证和进行接口访问……

![在这里插入图片描述](https://img-blog.csdnimg.cn/20200529165954598.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NDMxNjUyNw==,size_16,color_FFFFFF,t_70)

点击这里>[CSDN项目博客地址-SpringBoot集成JWT实现token验证](https://blog.csdn.net/weixin_44316527/article/details/106357414)

点击这里>[Github项目源码地址-SpringBoot集成JWT实现token验证](https://github.com/ChuaWi/SpringBoot-JWT)

[学习网址：SpringBoot集成JWT实现token](https://www.jianshu.com/p/e88d3f8151db)
 
