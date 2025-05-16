# tinyKernelHook

#### 1. 基本原理

​	借用windows使用的`int 2e`异常劫持控制流。

 #### 2. 用法

​	Hook的目的是劫持控制流，引导其执行预定义的操作，因此需要使用者自定义Hook函数。

![image-20250516113323347](D:\tools\Visual Studio\projects\tinyKernelHook\img_passwd\README\image-20250516113323347.png)

![image-20250516112150234](D:\tools\Visual Studio\projects\tinyKernelHook\img_passwd\README\image-20250516112150234.png)

​	上图中使用`HOOKENTRY`宏，注册自定义的Hook函数；注意，不需要在Hook函数中再次调用被Hook的函数，因为在Hook函数执行完毕后，会自动恢复原函数的执行流。

​	![image-20250516112516224](D:\tools\Visual Studio\projects\tinyKernelHook\img_passwd\README\image-20250516112516224.png)

​	`hook.c`文件，用于存储用户自定的Hook函数，其参数是全体通用寄存器组成的栈帧。

![image-20250516112919924](D:\tools\Visual Studio\projects\tinyKernelHook\img_passwd\README\image-20250516112919924.png)

​	最后，使用`InstallHook`，指定函数所在模块、函数地址、自定义Hook的wrapper函数地址，就可以将控制流转移到自定义Hook函数，建议使用`KeGenericCallDpc`在多核间同步Hook。

#### 3. 总结

​	Hook注册流程如下：

1. 用户定义`INT64 __stdcall (*)(PREGContext pushedAqs)`类型的Hook函数。
2. 使用`HOOKENTRY`宏，在`hooks.asm`中进行记录。
3. 使用`InstallHook`函数，在`trapHook.c`文件`KeGenericCallDpc`回调例程`InitAndInstallHook`，正式注册Hook。

