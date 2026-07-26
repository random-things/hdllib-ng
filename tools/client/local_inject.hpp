#pragma once

// Local (out-of-process) inject / recommend / early-bird — former hdlinjector.
// argv points at the first arg after the "inject" subcommand.
int RunLocalInject(int argc, wchar_t** argv);
void PrintLocalInjectUsage();

// Local (out-of-process) unload / optional reload. argv after "unload" / "reload".
int RunLocalUnload(int argc, wchar_t** argv, int reload_default);
void PrintLocalUnloadUsage();
