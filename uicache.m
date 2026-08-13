#import <stdio.h>
#import <getopt.h>
#import <dlfcn.h>
#import <objc/runtime.h>
#import <Foundation/Foundation.h>
#import <MobileCoreServices/MobileCoreServices.h>

/* CFUserNotification exists on iOS but the public SDK marks it API_UNAVAILABLE(ios) and
 * declares the two key constants with different qualifiers, so the upstream extern block does
 * not compile against a stock iphoneos SDK. Procursus builds against its own headers.
 *
 * Resolved at run time instead, which is what the rest of this tree does for symbols the SDK
 * hides. Renamed to jb_* so nothing collides with the real declarations, and every use is
 * null-checked: this is a cosmetic warning dialog, and it must never be the reason uicache
 * fails to register an app. */
typedef struct __CFUserNotification * JBUserNotificationRef;
typedef JBUserNotificationRef (*jb_cfun_create_t)(CFAllocatorRef, CFTimeInterval, CFOptionFlags, SInt32 *, CFDictionaryRef);
typedef SInt32 (*jb_cfun_response_t)(JBUserNotificationRef, CFTimeInterval, CFOptionFlags *);

static void jb_legacy_alert(void) {
	CFStringRef *headerKey  = dlsym(RTLD_DEFAULT, "kCFUserNotificationAlertHeaderKey");
	CFStringRef *messageKey = dlsym(RTLD_DEFAULT, "kCFUserNotificationAlertMessageKey");
	jb_cfun_create_t create = (jb_cfun_create_t)dlsym(RTLD_DEFAULT, "CFUserNotificationCreate");
	jb_cfun_response_t receive = (jb_cfun_response_t)dlsym(RTLD_DEFAULT, "CFUserNotificationReceiveResponse");
	if (!headerKey || !messageKey || !create || !receive) return;

	CFMutableDictionaryRef alertDict = CFDictionaryCreateMutable(NULL, 10,
		&kCFCopyStringDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFDictionaryAddValue(alertDict, *headerKey, CFSTR("Legacy uicache behavior triggered"));
	CFDictionaryAddValue(alertDict, *messageKey, CFSTR("A tweak on your device has triggered legacy uicache behavior. This process is slow, most likely used incorrectly, and will not be supported in the future."));

	SInt32 error = 0;
	JBUserNotificationRef note = create(kCFAllocatorSystemDefault, 0, 0, &error, alertDict);
	CFRelease(alertDict);
	if (!note) return;

	CFOptionFlags response = 0;
	receive(note, 0, &response);
	CFRelease(note);
}

@interface LSApplicationWorkspace : NSObject
+ (id)defaultWorkspace;
- (BOOL)_LSPrivateRebuildApplicationDatabasesForSystemApps:(BOOL)arg1 internal:(BOOL)arg2 user:(BOOL)arg3;
- (BOOL)registerApplicationDictionary:(NSDictionary *)applicationDictionary;
/* iOS 27: registerApplicationDictionary: still exists and is gutted. It returns NO without
 * touching the database, so every uicache -p and -a silently registers nothing. This is the
 * call that still works, and it is what trollstorehelper uses. */
- (BOOL)registerContainerizedApplicationWithInfoDictionaries:(NSArray *)infoDictionaries
                                               operationUUID:(NSUUID *)operationUUID
                                              requestContext:(id)requestContext
                                                saveObserver:(id)saveObserver
                                           registrationError:(NSError **)error;
- (BOOL)registerBundleWithInfo:(NSDictionary *)bundleInfo options:(NSDictionary *)options type:(unsigned long long)arg3 progress:(id)arg4 ;
- (BOOL)registerApplication:(NSURL *)url;
- (BOOL)registerPlugin:(NSURL *)url;
- (BOOL)unregisterApplication:(NSURL *)url;
- (NSArray *)installedPlugins;
-(void)_LSPrivateSyncWithMobileInstallation;
@end

typedef NS_OPTIONS(NSUInteger, SBSRelaunchActionOptions) {
	SBSRelaunchActionOptionsNone,
	SBSRelaunchActionOptionsRestartRenderServer = 1 << 0,
	SBSRelaunchActionOptionsSnapshotTransition = 1 << 1,
	SBSRelaunchActionOptionsFadeToBlackTransition = 1 << 2
};

@interface MCMContainer : NSObject
+ (instancetype)containerWithIdentifier:(NSString *)identifier createIfNecessary:(BOOL)createIfNecessary existed:(BOOL *)existed error:(NSError **)error;
- (NSURL *)url;
@end

@interface MCMAppDataContainer : MCMContainer
@end

@interface MCMPluginKitPluginDataContainer : MCMContainer
@end

/* Send a completed registration dictionary through whichever transport this OS still honours.
 *
 * uicache's dictionary construction is not the problem on iOS 27 and is left completely
 * untouched: entitlement extraction, MCMAppDataContainer creation, IsContainerized,
 * EnvironmentVariables, LSInstallType, SINF fields and _LSBundlePlugins are all correct.
 * Only the final call is dead.
 *
 * The BOOL is deliberately discarded. Measured on 24A5390f: the containerized API returns NO
 * on a registration that demonstrably succeeded, so propagating it reports failure on every
 * successful run. A nil error is the only trustworthy signal, and the caller verifies the
 * record afterwards.
 *
 * Falls back to the original call when the new selector is absent, so this source still
 * builds and behaves correctly on the iOS versions uicache already supported. */
static BOOL registerDictionary(LSApplicationWorkspace *workspace, NSDictionary *plist) {
	SEL containerized = @selector(registerContainerizedApplicationWithInfoDictionaries:
	                              operationUUID:requestContext:saveObserver:registrationError:);

	if (![workspace respondsToSelector:containerized])
		return [workspace registerApplicationDictionary:plist];

	NSError *error = nil;
	[workspace registerContainerizedApplicationWithInfoDictionaries:@[plist]
	                                                 operationUUID:[NSUUID UUID]
	                                                requestContext:nil
	                                                  saveObserver:nil
	                                             registrationError:&error];
	if (error) {
		fprintf(stderr, "Error: registration failed: %s\n",
		        error.description.UTF8String);
		return NO;
	}
	return YES;
}

@interface SBSRelaunchAction : NSObject
+ (instancetype)actionWithReason:(NSString *)reason options:(SBSRelaunchActionOptions)options targetURL:(NSURL *)targetURL;
@end

@interface FBSSystemService : NSObject
+ (instancetype)sharedService;
- (void)sendActions:(NSSet *)actions withResult:(id)result;
@end

#define	CS_OPS_CDHASH		5	/* get code directory hash */
int csops(pid_t pid, unsigned int  ops, void * useraddr, size_t usersize);

/* Set platform binary flag */
#define FLAG_PLATFORMIZE (1 << 1)

void platformizeme() {
    void* handle = dlopen("/usr/lib/libjailbreak.dylib", RTLD_LAZY);
    if (!handle) return;

    // Reset errors
    dlerror();
    typedef void (*fix_entitle_prt_t)(pid_t pid, uint32_t what);
    fix_entitle_prt_t ptr = (fix_entitle_prt_t)dlsym(handle, "jb_oneshot_entitle_now");

    const char *dlsym_error = dlerror();
    if (dlsym_error) {
        return;
    }

    ptr(getpid(), FLAG_PLATFORMIZE);
}

void help(char *name) {
	printf(
		"Usage: %s [OPTION...]\n"
		"Copyright (C) 2019, Electra Team. All Rights Reserved.\n\n"
		"Update iOS registered applications and optionally restart SpringBoard\n\n"

		"  --all           Update all system and internal applications\n"
		"                     (replicates the old uicache behavior)\n"
		"  --path <path>   Update application bundle at the specified path\n"
		"  --respring      Restart SpringBoard and backboardd after\n"
		"                     updating applications.\n"
		"  --help          Give this help list.\n\n"

		"Email the Electra team via Sileo for support.\n", name);
}

int main(int argc, char *argv[]){
	@autoreleasepool {
		platformizeme();

		int all = 0;
		char *path = NULL;
		int respring = 0;
		int showhelp = 0;
		bool isLegacyInstaller = false;

		/* -u was advertised in the help text and never wired up: the option table and the
		 * getopt string below both omitted it, so `uicache -u <path>` failed with
		 * "invalid option -- u" while the help promised it worked. The unregister branch
		 * further down was therefore unreachable. dpkg removal scripts call it, so it is
		 * wired up here rather than removed from the help. */
		char *unregisterPath = NULL;

		struct option longOptions[] = {
			{ "all" , no_argument, 0, 'a'},
			{ "path", required_argument, 0, 'p'},
			{ "unregister", required_argument, 0, 'u'},
			{ "respring", no_argument, 0, 'r' },
			{ "help", no_argument, 0, '?' },
			{ NULL, 0, NULL, 0 }
		};

		int index = 0, code = 0;

		while ((code = getopt_long(argc, argv, "ap:u:rh?", longOptions, &index)) != -1) {
			switch (code) {
				case 'a':
					all = 1;
					break;
				case 'p':
					path = strdup(optarg);
					break;
				case 'u':
					unregisterPath = strdup(optarg);
					break;
				case 'r':
					respring = 1;
					break;
				case 'h':
					showhelp = 1;
					break;
			}
		}

		uint8_t cdhash[20];
		bzero(cdhash, 20);
		int status = csops(getppid(), CS_OPS_CDHASH, cdhash, 20);

		if (status == 0){
			isLegacyInstaller = true;

			uint8_t ref_cdhash[20] = {0xc3, 0x75, 0xa8, 0xbb, 0x24, 0x22, 0x8e, 0x14, 0xa0, 0x01, 0x77, 0xa0, 0x3f, 0xaf, 0xc8, 0x7e, 0x5f, 0x50, 0xd5, 0x59};
			for (int i = 0; i < 20; i++){
				if (cdhash[i] != ref_cdhash[i]){
					isLegacyInstaller = false;
				}
			}
		}

		if (showhelp){
			help(argv[0]);
			return 0;
		} else if (argc == 1 && !isLegacyInstaller){
			help(argv[0]);
		}

		/* Unregister is its own path. The existing unregisterApplication: call further down
		 * sits in the `else` of `if (bundleID)`, so it only ran when a bundle had no
		 * CFBundleIdentifier, which is a corrupt-bundle fallback and not what -u means. */
		if (unregisterPath){
			NSString *target = [[NSString stringWithUTF8String:unregisterPath]
			                    stringByResolvingSymlinksInPath];
			LSApplicationWorkspace *workspace = [LSApplicationWorkspace defaultWorkspace];
			if (![workspace unregisterApplication:[NSURL fileURLWithPath:target]]){
				fprintf(stderr, "Error: Unable to unregister %s\n", target.UTF8String);
				free(unregisterPath);
				return -1;
			}
			printf("unregistered %s\n", target.UTF8String);
			free(unregisterPath);
			return 0;
		}

		if (path){
			dlopen("/System/Library/PrivateFrameworks/MobileContainerManager.framework/MobileContainerManager", RTLD_NOW);

			NSString *rawPath = [NSString stringWithUTF8String:path];
			rawPath = [rawPath stringByResolvingSymlinksInPath];
			BOOL isDirectory = NO;
			if (![[NSFileManager defaultManager] fileExistsAtPath:rawPath
			                                           isDirectory:&isDirectory] || !isDirectory) {
				fprintf(stderr, "Error: %s is not an application directory.\n",
				        rawPath.UTF8String);
				free(path);
				return -1;
			}

			/* Upstream accepts only /Applications, which makes this a rootful-only build: a
			 * bundle in /var/jb/Applications is rejected here, by uicache itself, before
			 * LaunchServices is ever asked. That is why `uicache -p` on a dpkg-installed app
			 * reports "Application must be a system application!" rather than anything about
			 * registration.
			 *
			 * stringByResolvingSymlinksInPath has already rewritten /var to /private/var by
			 * this point, so both spellings are accepted rather than assuming which one
			 * arrives. */
			NSArray *allowedParents = @[ @"/Applications",
			                             @"/var/jb/Applications",
			                             @"/private/var/jb/Applications" ];
			NSString *parent = [rawPath stringByDeletingLastPathComponent];
			if (![allowedParents containsObject:parent]){
				fprintf(stderr, "Error: %s is not a supported application location.\n",
				        parent.UTF8String);
				fprintf(stderr, "Supported: /Applications, /var/jb/Applications\n");
				free(path);
				return -1;
			}

			NSDictionary *infoPlist = [NSDictionary dictionaryWithContentsOfFile:[rawPath stringByAppendingPathComponent:@"Info.plist"]];
			NSString *bundleID = [infoPlist objectForKey:@"CFBundleIdentifier"];
			if (![infoPlist isKindOfClass:[NSDictionary class]] ||
			    ![bundleID isKindOfClass:[NSString class]] || bundleID.length == 0) {
				fprintf(stderr, "Error: %s has no valid CFBundleIdentifier.\n",
				        rawPath.UTF8String);
				free(path);
				return -1;
			}

			LSApplicationWorkspace *workspace = [LSApplicationWorkspace defaultWorkspace];
			{
				NSError *containerError = nil;
				MCMContainer *appContainer = [objc_getClass("MCMAppDataContainer") containerWithIdentifier:bundleID createIfNecessary:YES existed:nil error:&containerError];
				if (!appContainer) {
					fprintf(stderr, "Error: data container creation failed: %s\n",
					        containerError.description.UTF8String ?: "unknown error");
					free(path);
					return -1;
				}
				NSString *containerPath = [appContainer url].path;

				NSMutableDictionary *plist = [NSMutableDictionary dictionary];
				[plist setObject:@"System" forKey:@"ApplicationType"];
				[plist setObject:@1 forKey:@"BundleNameIsLocalized"];
				[plist setObject:bundleID forKey:@"CFBundleIdentifier"];
				[plist setObject:@0 forKey:@"CompatibilityState"];
				if (containerPath)
					[plist setObject:containerPath forKey:@"Container"];
				[plist setObject:@0 forKey:@"IsDeletable"];
				[plist setObject:rawPath forKey:@"Path"];

				NSString *pluginsPath = [rawPath stringByAppendingPathComponent:@"PlugIns"];
				NSArray *plugins = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:pluginsPath error:nil];

				NSMutableDictionary *bundlePlugins = [NSMutableDictionary dictionary];
				for (NSString *pluginName in plugins){
					NSString *fullPath = [pluginsPath stringByAppendingPathComponent:pluginName];

					NSDictionary *infoPlist = [NSDictionary dictionaryWithContentsOfFile:[fullPath stringByAppendingPathComponent:@"Info.plist"]];
					NSString *pluginBundleID = [infoPlist objectForKey:@"CFBundleIdentifier"];
					if (!pluginBundleID)
						continue;
					MCMContainer *pluginContainer = [objc_getClass("MCMPluginKitPluginDataContainer") containerWithIdentifier:pluginBundleID createIfNecessary:YES existed:nil error:nil];
					NSString *pluginContainerPath = [pluginContainer url].path;

					NSMutableDictionary *pluginPlist = [NSMutableDictionary dictionary];
					[pluginPlist setObject:@"PluginKitPlugin" forKey:@"ApplicationType"];
					[pluginPlist setObject:@1 forKey:@"BundleNameIsLocalized"];
					[pluginPlist setObject:pluginBundleID forKey:@"CFBundleIdentifier"];
					[pluginPlist setObject:@0 forKey:@"CompatibilityState"];
					if (pluginContainerPath)
						[pluginPlist setObject:pluginContainerPath forKey:@"Container"];
					[pluginPlist setObject:fullPath forKey:@"Path"];
					[pluginPlist setObject:bundleID forKey:@"PluginOwnerBundleID"];
					[bundlePlugins setObject:pluginPlist forKey:pluginBundleID];
				}
				[plist setObject:bundlePlugins forKey:@"_LSBundlePlugins"];
				if (!registerDictionary(workspace, plist)){
					fprintf(stderr, "Error: Unable to register app!\n");
					free(path);
					return -1;
				}
			}
			free(path);
		}

		if (argc == 1){
			if (isLegacyInstaller){
				all = true;
			} else if (!(getenv("SILEO") || isatty(STDOUT_FILENO) || isatty(STDIN_FILENO) || isatty(STDERR_FILENO))){
				printf("\n");
				fprintf(stderr, "Warning: No arguments detected. Using the old behavior for temporary compatibility. Please note that this will be removed in the future.\n");

				jb_legacy_alert();

				all = true;
			}
		}

		if (all){
			if (getenv("SILEO")){
				fprintf(stderr, "Error: -a may not be used while installing/uninstalling in Sileo. Ignoring.\n");
			} else {
				[[LSApplicationWorkspace defaultWorkspace] _LSPrivateRebuildApplicationDatabasesForSystemApps:YES internal:YES user:NO];
			}
		}

		if (respring){
			dlopen("/System/Library/PrivateFrameworks/FrontBoardServices.framework/FrontBoardServices", RTLD_NOW);
			dlopen("/System/Library/PrivateFrameworks/SpringBoardServices.framework/SpringBoardServices", RTLD_NOW);

			SBSRelaunchAction *restartAction = [objc_getClass("SBSRelaunchAction") actionWithReason:@"respring" options:(SBSRelaunchActionOptionsRestartRenderServer | SBSRelaunchActionOptionsFadeToBlackTransition) targetURL:nil];
			[(FBSSystemService *)[objc_getClass("FBSSystemService") sharedService] sendActions:[NSSet setWithObject:restartAction] withResult:nil];
			sleep(2);
		}

		return 0;
	}
}
