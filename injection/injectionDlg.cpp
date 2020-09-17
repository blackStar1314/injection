// injectionDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "injection.h"
#include <sstream>
#include "injectionDlg.h"
#include "afxdialogex.h"
#include <zeus/foundation/string/charset_utils.h>
#include <zeus/foundation/system/process.h>
#include <zeus/foundation/core/auto_handle.h>
#include <zeus/foundation/core/auto_module.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

// CinjectionDlg 对话框

CinjectionDlg::CinjectionDlg(CWnd* pParent /*=NULL*/)
    : CDialogEx(IDD_INJECTION_DIALOG, pParent)
{
    m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CinjectionDlg::DoDataExchange(CDataExchange* pDX)
{
    CDialogEx::DoDataExchange(pDX);
    DDX_Control(pDX, IDC_PROCESS_LIST, process_list_ctrl_);
}

BEGIN_MESSAGE_MAP(CinjectionDlg, CDialogEx)
    ON_WM_PAINT()
    ON_WM_QUERYDRAGICON()
    ON_NOTIFY(NM_RCLICK, IDC_PROCESS_LIST, &CinjectionDlg::OnRclickProcessList)
    ON_COMMAND(ID_A_INJECT, &CinjectionDlg::OnAInject)
END_MESSAGE_MAP()

// CinjectionDlg 消息处理程序

BOOL CinjectionDlg::OnInitDialog()
{
    CDialogEx::OnInitDialog();

    // 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
    //  执行此操作
    SetIcon(m_hIcon, TRUE);         // 设置大图标
    SetIcon(m_hIcon, FALSE);        // 设置小图标

    // TODO: 在此添加额外的初始化代码
  /*  DWORD pId = 21708;
    CString dll_path_name = L"E:\\windows_test\\windows\\wndApiExportDll\\Debug\\wndApiExportDll.dll";
    Inject(pId, dll_path_name);*/
    OnInitCtrl();
    EnumProcessList();
    return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CinjectionDlg::OnPaint()
{
    if (IsIconic())
    {
        CPaintDC dc(this); // 用于绘制的设备上下文

        SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

        // 使图标在工作区矩形中居中
        int cxIcon = GetSystemMetrics(SM_CXICON);
        int cyIcon = GetSystemMetrics(SM_CYICON);
        CRect rect;
        GetClientRect(&rect);
        int x = (rect.Width() - cxIcon + 1) / 2;
        int y = (rect.Height() - cyIcon + 1) / 2;

        // 绘制图标
        dc.DrawIcon(x, y, m_hIcon);
    }
    else
    {
        CDialogEx::OnPaint();
    }
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CinjectionDlg::OnQueryDragIcon()
{
    return static_cast<HCURSOR>(m_hIcon);
}

void CinjectionDlg::OnInitCtrl()
{
    CRect rt;
    process_list_ctrl_.GetWindowRect(&rt);
    auto width_avage = rt.Width() / 3;
    auto style = process_list_ctrl_.GetExtendedStyle();
    process_list_ctrl_.SetExtendedStyle(style | LVS_EX_GRIDLINES | LVS_EX_SINGLEROW);
    process_list_ctrl_.InsertColumn(0, L"PID", LVCFMT_LEFT, width_avage);
    process_list_ctrl_.InsertColumn(1, L"BITS", LVCFMT_LEFT, width_avage);
    process_list_ctrl_.InsertColumn(2, L"NAME", LVCFMT_LEFT, width_avage);
    process_list_ctrl_.InsertColumn(3, L"EXECUTEPATH", LVCFMT_LEFT, width_avage);
}

void CinjectionDlg::EnumProcessList()
{
    auto process = Zeus::Process::ListProcess();

    CString fmt;
    int index = 0;
    for (const auto& p : process)
    {
        fmt.Format(L"%d", p.Id());
        process_list_ctrl_.InsertItem(index, fmt);
        process_list_ctrl_.SetItemText(index, 1, IsWow64Process(p.Id()) ? L"32" : L"64");
        process_list_ctrl_.SetItemText(index, 2, Zeus::CharsetUtils::UTF8ToUnicode(p.Name()).c_str());
        process_list_ctrl_.SetItemText(index++, 3, Zeus::CharsetUtils::UTF8ToUnicode(p.ExePath()).c_str());
    }
}

int CinjectionDlg::GetSelectedItem(CListCtrl* list_ctrl)
{
    POSITION pos = list_ctrl->GetFirstSelectedItemPosition();
    int selected = -1;
    if (pos != NULL)
    {
        while (pos)
        {
            int nItem = list_ctrl->GetNextSelectedItem(pos);
            selected = nItem + 1;
        }
    }
    //returns -1 if not selected;
    return selected;
}

bool CinjectionDlg::IsWow64Process(DWORD pid)
{
    Zeus::AutoHandle hProcess = ::OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (*hProcess == NULL)
    {
        auto ec = ::GetLastError();
        return false;
    }
    BOOL wow64 = FALSE;
    if (!::IsWow64Process(*hProcess, &wow64))
    {
        auto ec = ::GetLastError();
    }
    return wow64 ? true : false;
}

bool CinjectionDlg::Inject(DWORD pId, const CString& path_name)
{
    // Get handle of the special process by id
    Zeus::AutoHandle hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, pId);
    if (*hProcess == NULL)
    {
        auto ec = ::GetLastError();
        return false;
    }

    // Reserves, commits, or changes the state of a region of memory within the virtual address space of a specified process.
    int size = path_name.GetLength();
    auto base_addr_page = ::VirtualAllocEx(*hProcess, nullptr, size * sizeof(WCHAR), MEM_COMMIT, PAGE_READWRITE);
    if (base_addr_page == NULL)
    {
        auto ec = ::GetLastError();
        return false;
    }

    // write dll path to virtual address of alloc
    SIZE_T write_bytes = 0;
    auto ret = ::WriteProcessMemory(*hProcess, base_addr_page, path_name, size * sizeof(WCHAR), &write_bytes);
    if (!ret)
    {
        auto ec = ::GetLastError();
        return false;
    }

    // Get LoadLibraryW function call addr
    Zeus::AutoModule hLib = ::LoadLibraryW(L"Kernel32");
    if (hLib.Module() == NULL)
    {
        auto ec = ::GetLastError();
        return false;
    }

    typedef HMODULE(__stdcall* LOADLIBRARYW)(LPCWSTR);
    LOADLIBRARYW start_routing = (LOADLIBRARYW)::GetProcAddress(hLib.Module(), "LoadLibraryW");

    Zeus::AutoHandle hRemote_process = ::CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)start_routing, base_addr_page, 0, nullptr);
    if (*hRemote_process == NULL)
    {
        auto ec = ::GetLastError();
        return false;
    }

    return true;
}

void CinjectionDlg::OnRclickProcessList(NMHDR* pNMHDR, LRESULT* pResult)
{
    LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);
    if (pNMItemActivate->iItem == -1)
    {
        *pResult = 0;
        return;
    }
    CMenu menu;
    VERIFY(menu.LoadMenuW(IDR_RCLK_MENU));
    CMenu* popup = menu.GetSubMenu(1);
    if (popup)
    {
        auto index = pNMItemActivate->iItem;
        if (index >= 0)
        {
            auto str_pid = process_list_ctrl_.GetItemText(index, 0);
            std::wstringstream wss;
            wss << str_pid.GetBuffer();
            wss >> pid_;
            str_pid.ReleaseBuffer();
        }

        DWORD pos = GetMessagePos();
        CPoint pt{ LOWORD(pos), HIWORD(pos) };
        popup->TrackPopupMenu(TPM_LEFTALIGN | TPM_RIGHTBUTTON, pt.x, pt.y, this);
    }

    *pResult = 0;
}

void CinjectionDlg::OnAInject()
{
    // 弹出选择文件框
    CFileDialog file_dlg(TRUE, L"", L"", OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT, L"Dynamic Library Link(*.dll)|*.dll||");
    file_dlg.DoModal();
    auto path_name = file_dlg.GetPathName();

    if (path_name.IsEmpty())
    {
        MessageBox(L"file path is empty!!", L"WARRING", MB_ICONWARNING);
        return;
    }
    bool inject = Inject(pid_, path_name);
    CString tip(L"inject dll ");
    tip += inject ? L"successfully " : L"failed";
    MessageBox(tip, L"TIP", inject ? MB_OK : MB_ICONERROR);
}
