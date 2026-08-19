#include "imgui.h"
#include "backends/imgui_impl_opengl3.h"
#include <GL/glx.h>
#include <GL/gl.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/Xatom.h>
#include <X11/keysym.h>
#include <X11/XKBlib.h>
#include <unistd.h>
#include <string>
#include <cstring>
#include <climits>
#include "app.h"

static Display* g_display = nullptr;
static Window g_window;
static GLXContext g_glCtx;
static Atom g_wmDelete;
static App* g_app = nullptr;

static std::string g_clipboard_cache;
static bool g_clipboard_ready = false;
static bool g_pending_paste = false;
static Atom g_clipboard_prop = 0;
static std::string g_owned_clipboard_text;

const char* GetClipboardTextFn(void* user_data) {
    if (g_clipboard_ready) {
        return g_clipboard_cache.c_str();
    }
    return "";
}

void SetClipboardTextFn(void* user_data, const char* text) {
    g_owned_clipboard_text = text;
    Atom selection = XInternAtom(g_display, "CLIPBOARD", False);
    XSetSelectionOwner(g_display, selection, g_window, CurrentTime);
    XFlush(g_display);
}

void RequestClipboardText() {
    Atom selection = XInternAtom(g_display, "CLIPBOARD", False);
    Window owner = XGetSelectionOwner(g_display, selection);
    if (owner == None) return;

    Atom target = XInternAtom(g_display, "UTF8_STRING", False);
    g_clipboard_prop = XInternAtom(g_display, "IMGUI_CLIPBOARD", False);
    XConvertSelection(g_display, selection, target, g_clipboard_prop, g_window, CurrentTime);
    XFlush(g_display);
}

void HandleSelectionRequest(const XSelectionRequestEvent& req) {
    XSelectionEvent notify = {};
    notify.type = SelectionNotify;
    notify.display = req.display;
    notify.requestor = req.requestor;
    notify.selection = req.selection;
    notify.target = req.target;
    notify.time = req.time;
    notify.property = None;

    Atom targetsAtom = XInternAtom(g_display, "TARGETS", False);
    Atom utf8Atom = XInternAtom(g_display, "UTF8_STRING", False);

    if (req.target == targetsAtom) {
        Atom supported[] = { targetsAtom, utf8Atom, XA_STRING };
        XChangeProperty(g_display, req.requestor, req.property, XA_ATOM, 32,
                         PropModeReplace, (unsigned char*)supported, 3);
        notify.property = req.property;
    } else if (req.target == utf8Atom || req.target == XA_STRING) {
        XChangeProperty(g_display, req.requestor, req.property, req.target, 8,
                         PropModeReplace,
                         (unsigned char*)g_owned_clipboard_text.c_str(),
                         (int)g_owned_clipboard_text.size());
        notify.property = req.property;
    }

    XSendEvent(g_display, req.requestor, False, 0, (XEvent*)&notify);
    XFlush(g_display);
}

bool CreateWindow() {
    g_display = XOpenDisplay(nullptr);
    if (!g_display) return false;
    int screen = DefaultScreen(g_display);
    Window root = RootWindow(g_display, screen);
    int glxAttribs[] = { GLX_RGBA, GLX_DOUBLEBUFFER, GLX_RED_SIZE, 8,
                         GLX_GREEN_SIZE, 8, GLX_BLUE_SIZE, 8, None };
    XVisualInfo* vi = glXChooseVisual(g_display, screen, glxAttribs);
    if (!vi) return false;
    Colormap cmap = XCreateColormap(g_display, root, vi->visual, AllocNone);
    XSetWindowAttributes swa = {};
    swa.colormap = cmap;
    swa.event_mask = ExposureMask | KeyPressMask | KeyReleaseMask |
                     ButtonPressMask | ButtonReleaseMask | PointerMotionMask |
                     StructureNotifyMask | FocusChangeMask;
    g_window = XCreateWindow(g_display, root, 100, 100, 1100, 720, 0,
                              vi->depth, InputOutput, vi->visual,
                              CWColormap | CWEventMask, &swa);
    XStoreName(g_display, g_window, "VirusTotal Scanner Pro");
    XMapWindow(g_display, g_window);
    g_wmDelete = XInternAtom(g_display, "WM_DELETE_WINDOW", False);
    XSetWMProtocols(g_display, g_window, &g_wmDelete, 1);
    g_glCtx = glXCreateContext(g_display, vi, nullptr, GL_TRUE);
    glXMakeCurrent(g_display, g_window, g_glCtx);
    XFree(vi);
    return true;
}

void CleanupWindow() {
    if (g_glCtx) { glXDestroyContext(g_display, g_glCtx); g_glCtx = nullptr; }
    if (g_window) { XDestroyWindow(g_display, g_window); g_window = 0; }
    if (g_display) { XCloseDisplay(g_display); g_display = nullptr; }
}

std::string GetFontPath() {
    const char* fonts[] = {
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
        "/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf",
        "/usr/share/fonts/truetype/ubuntu/Ubuntu-Regular.ttf",
        "/usr/share/fonts/truetype/arial/arial.ttf",
        nullptr
    };
    for (int i = 0; fonts[i]; ++i) {
        if (access(fonts[i], R_OK) == 0) return fonts[i];
    }
    return "";
}

int main() {
    if (!CreateWindow()) return 1;
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.IniFilename = nullptr;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

    io.GetClipboardTextFn = GetClipboardTextFn;
    io.SetClipboardTextFn = SetClipboardTextFn;

    io.DisplaySize = ImVec2(1100.0f, 720.0f);

    std::string fontPath = GetFontPath();
    if (!fontPath.empty()) {
        ImFontConfig cfg;
        cfg.OversampleH = 2;
        cfg.OversampleV = 2;
        io.Fonts->AddFontFromFileTTF(fontPath.c_str(), 17.0f, &cfg, io.Fonts->GetGlyphRangesCyrillic());
    } else {
        io.Fonts->AddFontDefault();
    }
    ImGui::StyleColorsDark();
    ImGuiStyle& style = ImGui::GetStyle();
    style.WindowRounding = 6.0f;
    style.FrameRounding = 4.0f;
    style.GrabRounding = 4.0f;
    ImGui_ImplOpenGL3_Init("#version 330");
    App app;
    g_app = &app;
    app.Init(nullptr);
    bool done = false;

    while (!done) {
        XEvent event;
        while (XPending(g_display)) {
            XNextEvent(g_display, &event);

            if (event.type == ClientMessage && (Atom)event.xclient.data.l[0] == g_wmDelete) {
                done = true;
            }

            if (event.type == ConfigureNotify) {
                XConfigureEvent xev = event.xconfigure;
                io.DisplaySize = ImVec2((float)xev.width, (float)xev.height);
            }

            if (event.type == MotionNotify) {
                io.AddMousePosEvent((float)event.xmotion.x, (float)event.xmotion.y);
            }

            if (event.type == ButtonPress || event.type == ButtonRelease) {
                int button = -1;
                if (event.xbutton.button == Button1) button = ImGuiMouseButton_Left;
                if (event.xbutton.button == Button2) button = ImGuiMouseButton_Middle;
                if (event.xbutton.button == Button3) button = ImGuiMouseButton_Right;
                if (button != -1) {
                    io.AddMouseButtonEvent(button, event.type == ButtonPress);
                }
            }

            if (event.type == SelectionRequest) {
                HandleSelectionRequest(event.xselectionrequest);
            }

            if (event.type == SelectionNotify) {
                XSelectionEvent& sel = event.xselection;
                if (sel.property != None) {
                    Atom actual_type;
                    int actual_format;
                    unsigned long nitems, bytes_after;
                    unsigned char* data = nullptr;

                    XGetWindowProperty(g_display, g_window, sel.property, 0, LONG_MAX, False, AnyPropertyType,
                                      &actual_type, &actual_format, &nitems, &bytes_after, &data);

                    if (data && nitems > 0) {
                        g_clipboard_cache = std::string((char*)data, nitems);
                        g_clipboard_ready = true;

                        if (g_pending_paste) {
                            io.AddInputCharactersUTF8(g_clipboard_cache.c_str());
                            g_pending_paste = false;
                        }

                        XFree(data);
                    }
                } else {
                    g_pending_paste = false;
                }
            }

            if (event.type == KeyPress || event.type == KeyRelease) {
                bool isPress = (event.type == KeyPress);
                XKeyEvent& xkey = event.xkey;
                KeySym keysym = XLookupKeysym(&xkey, 0);

                bool ctrl = (xkey.state & ControlMask) != 0;
                bool shift = (xkey.state & ShiftMask) != 0;

                io.AddKeyEvent(ImGuiKey_LeftCtrl, ctrl);
                io.AddKeyEvent(ImGuiKey_LeftShift, shift);
                io.AddKeyEvent(ImGuiKey_LeftAlt, (xkey.state & Mod1Mask) != 0);

                if (isPress && ctrl) {
                    ImGuiKey key = ImGuiKey_None;

                    if (keysym == XK_c || keysym == XK_C) {
                        key = ImGuiKey_C;
                    } else if (keysym == XK_v || keysym == XK_V) {
                        key = ImGuiKey_V;
                        g_pending_paste = true;
                        RequestClipboardText();
                    } else if (keysym == XK_x || keysym == XK_X) {
                        key = ImGuiKey_X;
                    } else if (keysym == XK_a || keysym == XK_A) {
                        key = ImGuiKey_A;
                    } else if (keysym == XK_z || keysym == XK_Z) {
                        key = ImGuiKey_Z;
                    }

                    if (key != ImGuiKey_None) {
                        io.AddKeyEvent(key, true);
                        io.AddKeyEvent(key, false);
                    }
                } else {
                    ImGuiKey imgui_key = ImGuiKey_None;
                    if (keysym >= XK_a && keysym <= XK_z) {
                        imgui_key = (ImGuiKey)(ImGuiKey_A + (keysym - XK_a));
                    } else if (keysym >= XK_A && keysym <= XK_Z) {
                        imgui_key = (ImGuiKey)(ImGuiKey_A + (keysym - XK_A));
                    } else if (keysym >= XK_0 && keysym <= XK_9) {
                        imgui_key = (ImGuiKey)(ImGuiKey_0 + (keysym - XK_0));
                    } else if (keysym == XK_BackSpace) imgui_key = ImGuiKey_Backspace;
                    else if (keysym == XK_Tab) imgui_key = ImGuiKey_Tab;
                    else if (keysym == XK_Return) imgui_key = ImGuiKey_Enter;
                    else if (keysym == XK_Escape) imgui_key = ImGuiKey_Escape;
                    else if (keysym == XK_Delete) imgui_key = ImGuiKey_Delete;
                    else if (keysym == XK_Left) imgui_key = ImGuiKey_LeftArrow;
                    else if (keysym == XK_Right) imgui_key = ImGuiKey_RightArrow;
                    else if (keysym == XK_Up) imgui_key = ImGuiKey_UpArrow;
                    else if (keysym == XK_Down) imgui_key = ImGuiKey_DownArrow;
                    else if (keysym == XK_Home) imgui_key = ImGuiKey_Home;
                    else if (keysym == XK_End) imgui_key = ImGuiKey_End;
                    else if (keysym == XK_Page_Up) imgui_key = ImGuiKey_PageUp;
                    else if (keysym == XK_Page_Down) imgui_key = ImGuiKey_PageDown;
                    else if (keysym == XK_Insert) imgui_key = ImGuiKey_Insert;

                    if (imgui_key != ImGuiKey_None) {
                        io.AddKeyEvent(imgui_key, isPress);
                    }
                }

                if (isPress && !ctrl) {
                    char buf[32] = {};
                    int len = XLookupString(&xkey, buf, sizeof(buf), nullptr, nullptr);
                    if (len > 0) {
                        io.AddInputCharactersUTF8(buf);
                    }
                }
            }
        }

        if (app.WantsExit()) done = true;

        ImGui_ImplOpenGL3_NewFrame();
        ImGui::NewFrame();

        app.DrawUI();

        ImGui::Render();
        glViewport(0, 0, (int)io.DisplaySize.x, (int)io.DisplaySize.y);
        glClearColor(0.08f, 0.08f, 0.10f, 1.00f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        glXSwapBuffers(g_display, g_window);
        usleep(10000);
    }
    ImGui_ImplOpenGL3_Shutdown();
    ImGui::DestroyContext();
    CleanupWindow();
    return 0;
}
