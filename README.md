# cpp-httplib--

基于cpp-httplib的改造版本，目前在windows环境改造成功。  

改造点：  
1）头文件只包含基本类型，去掉对其他头文件的包含，避免由头文件重复包含导致的编译问题（比如socket库头文件  
2）把头文件中的函数定义移到.cpp文件。  


