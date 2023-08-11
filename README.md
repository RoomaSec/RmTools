# RmTools
蓝队应急工具  
防呆提示: 必须右键以管理员运行此工具.否做功能会失效  
最低版本: windows7 x64  

### 更新日志

2023/8/3:

door_scanner-alpha更新 ioc扫描 支持银狐扫描

2023/7/22:

yara scanner推出测试版,多线程扫描,大量优化改进,5分钟扫描完全盘.支持导出报表,具体可以看`yara scanner beta`目录

2022/10/18:  
door scanner推出测试版,测试版增加prefetch搜集功能,修复了一些bug

2022/10/08:  
memory scanner支持windows7了!现在windows7 sp1与windows 2008能使用此工具了!  

### 工具列表
1. yara scanner
这个是应急用的给朋友定制的,他们说一个公司发现了一个病毒基本上其他的机器都有同样的文件只不过位置不一样要一个东西能全扫出来.功能列表:
```
1. 全盘文件扫描,寻找指定的hash、文件名
2. yara扫描,可自定义yara文件进行扫描查找
3. ntfs stream流扫描,检测文件是否携带了ntfs stream数据
4. 导出报告
```
配置项注释:
```
{
    "scan_path": ["D:\\system_image"], //扫描的目录.不要以\\结尾,可以是磁盘根目录
    "hashes": [
        "EE9E2816170E9441690EBEE28324F43046056712" //要找的文件的hash,这是个数组
    ],
    "filenames": [
        "InstDrv.bin" //要找的文件名字,这是模糊匹配,这是个数组
    ],
	"max_file_limit": 5002400 //最大读取文件的大小,超过这个大小的文件不读取
}
```
可以编辑yara_rules目录,从而让这个工具变成webshell扫描工具、木马病毒扫描工具、特定信息扫描工具等等.自己配置yara
请确保有yara文件,否做工具无法运行

2. door scanner
这个是应急用的给朋友定制的,主要用途扫描持久化后门,功能列表:
```
1. 扫描计划任务、注册表自启动、开始菜单自启动、服务的项目
2. 扫描dns缓存
3. 扫描TCP表
4. 扫描用户列表
6. 扫描amcache,扫描历史程序启动记录[最低支持: windows8]
7. 扫描登录日志,检测登录主机名、IP、检测RDP爆破[最低支持: windows7]
8. 扫描域控日志,检测hash传递、万能钥匙域控横向移动[最低支持: windows7]
9. PowerShell执行历史记录扫描[最低支持: windows7]
10. [beta测试版]prefetch扫描,获取最近的程序执行记录
11. [beta测试版]runmru扫描,获取所有用户最近的通过"win+r运行"执行的程序
12. [beta测试版]shimcache扫描,获取最近程序执行记录
13. [beta测试版]AppCompatFlags扫描,获取最近程序执行记录
14. [beta测试版]Muicache扫描,获取最近程序执行记录
15. [beta测试版]rdp服务(3389)对外远程链接记录
16. [beta测试版]rdp服务(3389)对内远程链接记录
17. 对以上这些项目对接IOC进行检查,检查hash、IP、域名,标注可疑项目(需要自己申请APIKEY)
18. 支持CSV报表导出
```
*代表正在内测稳定性,暂不公布,加入社区一起内测

 好消息!离线扫描脚本已经就绪,支持离线云查扫描!

编辑`offline_scan.py` 填入你的API,然后选择要打开的CSV文件

```
headers = {
    'apikey': "你的API key"
}
csvfile = open('./shimcache.csv', 'r')
```

就可以把隔离网的进程信息进行离线云查扫描了!

配置项注释:

```
{
    "apikey": "", //ioc的apikey,不配置默认不用ioc
    "max_file_limit": 10737418240 //最大读取文件的大小,超过这个大小的文件不读取
}
```
3. memory scan
这个是之前duckmemoryscan的进化版本,主要用途扫描内存后门,功能列表:
```
1. 扫描内存马(任何在heap上的内存马,如cobalt strike、msf,xor、aes免杀loader等xxxoo变种)
2. 标注内存中可疑的位置的进程、线程信息
3. yara内存扫描,默认规则扫描内存中是否存在ip、域名、PE文件
4. 标注可疑的dll.如伪装成系统程序的dll、无数字签名的dll却加载到有数字签名的进程中
5. 标注可疑的dll行为,如RPC dump lsass等
6. 标注无数字签名的进程
7. 扫描rootkit,检测是否有可疑的驱动程序
8. 在有IOC情报源的情况下,扫描危险进程、高危dll
9. 支持CSV报表导出
```
配置项注释:
```
{
    "apikey": "", //ioc的apikey,不配置默认不用ioc
	"ioc_scan_dll": 0, //是否用IOC扫描DLL,如果扫描的话会给出dll文件的安全性,但是会慢
    "max_file_limit": 5002400 //最大读取文件的大小,超过这个大小的文件不读取
}

```
可以编辑yara_rules目录,默认yara检测cobalt strike的beacon.也可以写其他的规则,比如扫描内存中是否有IP地址、是否有域名啥的,看yara编写配置.
请确保有yara文件,否做工具无法运行

4. 待做项目:
```
由于目前工作繁忙原因,以下东西在待做列表中,按照顺序,优先实现.请star这个项目保持关注:
1.yara scanner for linux
2.door scanner for linux
3.memory scanner for linux
4.weblog scanner
```
### IOC情报源
所有工具都依赖 https://metadefender.opswat.com/ 的IOC情报源,您需要注册后,编辑工具对应的config.json,将里面的apikey改成自己的即可.为空代表不使用IOC情报源.

## Yara规则来源

Yara规则来自:

https://github.com/elastic/protections-artifacts



### 免责声明【使用本工具则代表同意】
本系列工具会对系统磁盘进行读写(找文件、扫文件)等,硬盘不好的电脑会卡顿,如果恰好硬盘年久失修或者其他原因啥的用了本工具有一定几率会被读坏(比如10年老硬盘,本来快坏了、或者【在扫描磁盘的时候被断电了】这种情况)  
因为本系列工具造成的【数据损失】、【磁盘损坏】,本工具的作者、组织不负任何责任!!!!!!
虽然以上事件发生几率很小很小很小小到可以忽略不计,而且每个系统中的每个程序都有这种风险.但是为了避免不必要的纠纷,一旦您使用了本系列工具,【代表您默认同意这个免责声明】,并且在使用本系列工具的过程中【出现的问题您自己负责】
