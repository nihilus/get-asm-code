///////////////////////////////////////////////////////////////////////////////
//
//  File     : Get AsmCode.cpp
//  Author   : obaby
//  Date     : 14/06/2012
//  Homepage : http://www.h4ck.ws
//  
//  License  : Copyright ?2012 火星信息安全研究院
//
//  This software is provided 'as-is', without any express or
//  implied warranty. In no event will the authors be held liable
//  for any damages arising from the use of this software.
//
///////////////////////////////////////////////////////////////////////////////

//-----------------------------------------------------------------------------

#include "Get AsmCode.h"


// Global Variables:
int gSdkVersion;
char gszVersion[]      = "1.0.0.1";
// Plugin name listed in (Edit | Plugins)
char gszWantedName[]   = "Get AsmCode";
// plug-in hotkey
char gszWantedHotKey[] = "Shift+A";

char *gszPluginHelp;
char *gszPluginComment;



bool GetKernelVersion(char *szBuf, int bufSize)
{
	int major, minor, len;
	get_kernel_version(szBuf, bufSize);
	if ( qsscanf(szBuf, "%d.%n%d", &major, &len, &minor) != 2 )
		return false;
	if ( isdigit(szBuf[len + 1]) )
		gSdkVersion = 100*major + minor;
	else
		gSdkVersion = 10 * (10*major + minor);
	return true;
}

bool GenerateAsmLines(ea_t saddr,ea_t eaddr)
{
	int max_lines = 100;
	char **myLines= new char *[max_lines];
	int lnnum;
	// Buffer that will hold the disassembly text
	char buffer[MAXSTR];
	// Store the disassembled text in buf
	//generate_disasm_line(saddr, buffer, sizeof(buffer)-1);

	// This will appear as colour-tagged text (which will
	// be mostly unreadable in IDA's Log window)

	/*for (ea_t i = saddr;i <= eaddr; i += get_item_size(i))
	{
		char clean_buf[MAXSTR];
		
		generate_disasm_line(i, buffer, sizeof(buffer)-1);
		tag_remove(buffer,clean_buf,sizeof(clean_buf)-1);
		msg("Line %0.2d: %s \n",i,clean_buf);
	}*/
	
	for (ea_t i = saddr;i <= eaddr; i += get_item_size(i))
	{
		char clean_buf[MAXSTR];
		int nlines = generate_disassembly(i,myLines,max_lines,&lnnum,MAKELINE_STACK);
		for ( int j=0; j<nlines; j++ )
		{
			const char *buf = myLines[j];
			char clean_buf[MAXSTR];
			size_t line_len = strlen(buf);

			tag_remove(buf,clean_buf,sizeof(clean_buf)-1);
			msg("Line %0.2d: %s \n",j,clean_buf);

		}
	}
	return true;
}
//-----------------------------------------------------------------------------
// Function: init
//
// init is a plugin_t function. It is executed when the plugin is
// initially loaded by IDA.
// Three return codes are possible:
//    PLUGIN_SKIP - Plugin is unloaded and not made available
//    PLUGIN_KEEP - Plugin is kept in memory
//    PLUGIN_OK   - Plugin will be loaded upon 1st use
//
// Check are added here to ensure the plug-in is compatible with
// the current disassembly.
//-----------------------------------------------------------------------------
int initPlugin(void)
{
	char szBuffer[MAXSTR];
	char sdkVersion[32];
	int nRetCode = PLUGIN_OK;
	HINSTANCE hInstance = ::GetModuleHandle(NULL);

	// Initialize global strings
	LoadString(hInstance, IDS_PLUGIN_HELP, szBuffer, sizeof(szBuffer));
	gszPluginHelp = qstrdup(szBuffer);
	LoadString(hInstance, IDS_PLUGIN_COMMENT, szBuffer, sizeof(szBuffer));
	gszPluginComment = qstrdup(szBuffer);
	if ( !GetKernelVersion(sdkVersion, sizeof(sdkVersion)) )
	{
		msg("%s: could not determine IDA version\n", gszWantedName);
		nRetCode = PLUGIN_SKIP;
	}
	else if ( gSdkVersion < 610 )
	{
		warning("Sorry, the %s plugin required IDA v%s or higher\n", gszWantedName, sdkVersion);
		nRetCode = PLUGIN_SKIP;
	}
	else if ( ph.id != PLFM_386 || ( !inf.is_32bit() && !inf.is_64bit() ) || inf.like_binary() )
	{
		msg("%s: could not load plugin\n", gszWantedName);
		nRetCode = PLUGIN_SKIP;
	}
	else
	{
		msg( "%s (v%s) plugin has been loaded\n"
			"  The hotkeys to invoke the plugin is %s.\n"
			"  Please check the Edit/Plugins menu for more informaton.\n",
			gszWantedName, gszVersion, gszWantedHotKey);
	}
	return nRetCode;
}

//-----------------------------------------------------------------------------
// Function: term
//
// term is a plugin_t function. It is executed when the plugin is
// unloading. Typically cleanup code is executed here.
//-----------------------------------------------------------------------------
void termPlugin(void)
{
}

//-----------------------------------------------------------------------------
// Function: run
//
// run is a plugin_t function. It is executed when the plugin is run.
//
// The argument 'arg' can be passed by adding an entry in 
// plugins.cfg or passed manually via IDC:
//
//   success RunPlugin(string name, long arg);
//-----------------------------------------------------------------------------
void runPlugin(int arg)
{
	int myBufferSize;

	bool as_stack;
	char * idbpath;
	char * asmfile;
	FILE *fp ;
	func_t *func;
	qstring funcName;
	 
	ea_t eaddr, saddr , currentea= get_screen_ea();
	msg("\nGet AsmCode Start:\n");
	msg("--------------------------------------------------------------------------------------\n");
	msg("Start generate asm file at addr 0x%0.8X.....\n",currentea);

	if (currentea == BADADDR)
	{
		warning("Plz select a valid Address!\n");
		goto __Faild;
	}
	
	func = get_func(currentea);
	eaddr = func->endEA;
	saddr = func->startEA;
	
	get_func_name2(&funcName, saddr);

	msg("Function %s start at 0x%0.8X ,end at 0x%0.8X .\n",funcName.c_str(),saddr,eaddr);

	if (eaddr == BADADDR || saddr == BADADDR)
	{
		warning("Can't Get Function start or end address,plz check ur selection!\n");
		goto __Faild;
	}
	idbpath = database_idb;
	#undef strcat
	asmfile = strcat(idbpath,"_part.asm");
	fp = qfopen(asmfile, "w");
	gen_file(OFILE_ASM,fp,saddr,eaddr,0); //生成asm文件
	//gen_file(OFILE_ASM,fp,saddr,eaddr,GENFLG_ASMTYPE);
	qfclose(fp);
	msg("File is saved to :\n %s.\n",asmfile);

__Faild:
	msg("Generate Asmfile Finished.\n");
	msg("--------------------------------------------------------------------------------------\n");
//	msg("All returned lines %d!\n",nlines);
//  Uncomment the following code to allow plugin unloading.
//  This allows the editing/building of the plugin without
//  restarting IDA.
//
//  1. to unload the plugin execute the following IDC statement:
//        RunPlugin("Get AsmCode", 415);
//  2. Make changes to source code and rebuild within Visual Studio
//  3. Copy plugin to IDA plugin dir
//     (may be automatic if option was selected within wizard)
//  4. Run plugin via the menu, hotkey, or IDC statement
//
// 	if (arg == 415)
// 	{
// 		PLUGIN.flags |= PLUGIN_UNL;
// 		msg("Unloading Get AsmCode plugin...\n");
// 	}
}

///////////////////////////////////////////////////////////////////////////////
//
//                         PLUGIN DESCRIPTION BLOCK
//
///////////////////////////////////////////////////////////////////////////////
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  0,              // plugin flags
  initPlugin,           // initialize
  termPlugin,           // terminate. this pointer may be NULL.
  runPlugin,            // invoke plugin
  gszPluginComment,     // comment about the plugin
  gszPluginHelp,        // multiline help about the plugin
  gszWantedName,        // the preferred short name of the plugin
  gszWantedHotKey       // the preferred hotkey to run the plugin
};

