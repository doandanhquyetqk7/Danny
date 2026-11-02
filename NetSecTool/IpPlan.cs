using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;

namespace NetSecTool;

/// <summary>
/// Bang quy hoach dia chi IP cua cac don vi truc thuoc Bo CHQS tinh Lam Dong.
/// 
/// Sinh tu tai lieu goc: "DS dia chi IP WAN LAN LD.md" - khong sua tay,
/// nen danh sach luon khop voi tai lieu.
/// 
/// Cau truc moi don vi:
///   - LAN      : dai mang noi bo may tram (vi du 86.250.0.0/27)
///   - Gateway  : dia chi cua router noi bo trong LAN
///   - WAN      : dia chi IP wan cua modem tai don vi
///   - GW WAN   : dia chi default gateway o phia wan
/// </summary>
internal static class IpPlan
{
    /// <summary>Mot don vi trong danh sach quy hoach.</summary>
    internal sealed record Unit(
        int Index,
        string Name,
        string LanCidr,
        string SubnetMask,
        string LanGateway,
        string WanIp,
        string WanGateway);

    /// <summary>Toan bo danh sach don vi, sap xep theo so thu tu.</summary>
    public static readonly Unit[] All =
    {
        new Unit(1, "Ban CHQS phường Xuân Hương", "86.250.0.0/27", "255.255.255.224", "86.250.0.1", "86.250.220.1", "86.250.220.254"),
        new Unit(2, "Ban CHQS phường Cam Ly", "86.250.0.32/27", "255.255.255.224", "86.250.0.33", "86.250.220.3", "86.250.220.254"),
        new Unit(3, "Ban CHQS phường Lang Biang", "86.250.0.64/27", "255.255.255.224", "86.250.0.65", "86.250.220.5", "86.250.220.254"),
        new Unit(4, "Ban CHQS phường Xuân Trường", "86.250.0.96/27", "255.255.255.224", "86.250.0.97", "86.250.220.7", "86.250.220.254"),
        new Unit(5, "Ban CHQS phường Lâm Viên", "86.250.0.128/27", "255.255.255.224", "86.250.0.129", "86.250.220.9", "86.250.220.254"),
        new Unit(6, "Ban CHQS xã Lạc Dương", "86.250.0.160/27", "255.255.255.224", "86.250.0.161", "86.250.220.11", "86.250.220.254"),
        new Unit(7, "Ban CHQS xã Hiệp Thạnh", "86.250.0.192/27", "255.255.255.224", "86.250.0.193", "86.250.220.13", "86.250.220.254"),
        new Unit(8, "Ban CHQS xã Đức Trọng", "86.250.0.224/27", "255.255.255.224", "86.250.0.225", "86.250.220.15", "86.250.220.254"),
        new Unit(9, "Ban CHQS xã Tân Hội", "86.250.1.0/27", "255.255.255.224", "86.250.1.1", "86.250.220.17", "86.250.220.254"),
        new Unit(10, "Ban CHQS xã Ninh Gia", "86.250.1.32/27", "255.255.255.224", "86.250.1.33", "86.250.220.19", "86.250.220.254"),
        new Unit(11, "Ban CHQS xã Tà Hine", "86.250.1.64/27", "255.255.255.224", "86.250.1.65", "86.250.220.21", "86.250.220.254"),
        new Unit(12, "Ban CHQS xã Tà Năng", "86.250.1.96/27", "255.255.255.224", "86.250.1.97", "86.250.220.23", "86.250.220.254"),
        new Unit(13, "Ban CHQS xã Đơn Dương", "86.250.1.128/27", "255.255.255.224", "86.250.1.129", "86.250.220.25", "86.250.220.254"),
        new Unit(14, "Ban CHQS xã Ka Đô", "86.250.1.160/27", "255.255.255.224", "86.250.1.161", "86.250.220.27", "86.250.220.254"),
        new Unit(15, "Ban CHQS xã Quảng Lập", "86.250.1.192/27", "255.255.255.224", "86.250.1.193", "86.250.220.29", "86.250.220.254"),
        new Unit(16, "Ban CHQS xã Dran", "86.250.1.224/27", "255.255.255.224", "86.250.1.225", "86.250.220.31", "86.250.220.254"),
        new Unit(17, "Ban CHQS xã Đình Văn", "86.250.2.0/27", "255.255.255.224", "86.250.2.1", "86.250.220.33", "86.250.220.254"),
        new Unit(18, "Ban CHQS xã Nam Ban", "86.250.2.32/27", "255.255.255.224", "86.250.2.33", "86.250.220.35", "86.250.220.254"),
        new Unit(19, "Ban CHQS xã Phúc Thọ", "86.250.2.64/27", "255.255.255.224", "86.250.2.65", "86.250.220.37", "86.250.220.254"),
        new Unit(20, "Ban CHQS xã Nam Hà", "86.250.2.96/27", "255.255.255.224", "86.250.2.97", "86.250.220.39", "86.250.220.254"),
        new Unit(21, "Ban CHQS xã Phú Sơn", "86.250.2.128/27", "255.255.255.224", "86.250.2.129", "86.250.220.41", "86.250.220.254"),
        new Unit(22, "Ban CHQS xã Tân Hà", "86.250.2.160/27", "255.255.255.224", "86.250.2.161", "86.250.220.43", "86.250.220.254"),
        new Unit(23, "Ban CHQS xã Đam Rông 1", "86.250.2.192/27", "255.255.255.224", "86.250.2.193", "86.250.220.45", "86.250.220.254"),
        new Unit(24, "Ban CHQS xã Đam Rông 2", "86.250.2.224/27", "255.255.255.224", "86.250.2.225", "86.250.220.47", "86.250.220.254"),
        new Unit(25, "Ban CHQS xã Đam Rông 3", "86.250.3.0/27", "255.255.255.224", "86.250.3.1", "86.250.220.49", "86.250.220.254"),
        new Unit(26, "Ban CHQS xã Đam Rông 4", "86.250.3.32/27", "255.255.255.224", "86.250.3.33", "86.250.220.51", "86.250.220.254"),
        new Unit(27, "Ban CHQS xã Di Linh", "86.250.3.64/27", "255.255.255.224", "86.250.3.65", "86.250.220.53", "86.250.220.254"),
        new Unit(28, "Ban CHQS xã Đinh Trang Thượng", "86.250.3.96/27", "255.255.255.224", "86.250.3.97", "86.250.220.55", "86.250.220.254"),
        new Unit(29, "Ban CHQS xã Sơn Điền", "86.250.3.128/27", "255.255.255.224", "86.250.3.129", "86.250.220.57", "86.250.220.254"),
        new Unit(30, "Ban CHQS xã Bảo Thuận", "86.250.3.160/27", "255.255.255.224", "86.250.3.161", "86.250.220.59", "86.250.220.254"),
        new Unit(31, "Ban CHQS xã Gia Hiệp", "86.250.3.192/27", "255.255.255.224", "86.250.3.193", "86.250.220.61", "86.250.220.254"),
        new Unit(32, "Ban CHQS xã Hoà Ninh", "86.250.3.224/27", "255.255.255.224", "86.250.3.225", "86.250.220.63", "86.250.220.254"),
        new Unit(33, "Ban CHQS xã Hoà Bắc", "86.250.4.0/27", "255.255.255.224", "86.250.4.1", "86.250.220.65", "86.250.220.254"),
        new Unit(34, "Ban CHQS phường 1", "86.250.4.32/27", "255.255.255.224", "86.250.4.33", "86.250.220.67", "86.250.220.254"),
        new Unit(35, "Ban CHQS phường 2", "86.250.4.64/27", "255.255.255.224", "86.250.4.65", "86.250.220.69", "86.250.220.254"),
        new Unit(36, "Ban CHQS phường 3", "86.250.4.96/27", "255.255.255.224", "86.250.4.97", "86.250.220.71", "86.250.220.254"),
        new Unit(37, "Ban CHQS phường BLao", "86.250.4.128/27", "255.255.255.224", "86.250.4.129", "86.250.220.73", "86.250.220.254"),
        new Unit(38, "Ban CHQS xã Bảo Lâm 1", "86.154.132.0/24", "255.255.255.0", "86.154.132.254", "86.134.240.121", "86.134.240.113"),
        new Unit(39, "Ban CHQS xã Bảo Lâm 2", "86.250.4.192/27", "255.255.255.224", "86.250.4.193", "86.250.220.77", "86.250.220.254"),
        new Unit(40, "Ban CHQS xã Bảo Lâm 3", "86.250.4.224/27", "255.255.255.224", "86.250.4.225", "86.250.220.79", "86.250.220.254"),
        new Unit(41, "Ban CHQS xã Bảo Lâm 4", "86.250.5.0/27", "255.255.255.224", "86.250.5.1", "86.250.220.81", "86.250.220.254"),
        new Unit(42, "Ban CHQS xã Bảo Lâm 5", "86.250.5.32/27", "255.255.255.224", "86.250.5.33", "86.250.220.83", "86.250.220.254"),
        new Unit(43, "Ban CHQS xã Đạ Huoai", "86.250.5.64/27", "255.255.255.224", "86.250.5.65", "86.250.220.85", "86.250.220.254"),
        new Unit(44, "Ban CHQS xã Đạ Huoai 2", "86.250.5.96/27", "255.255.255.224", "86.250.5.97", "86.250.220.87", "86.250.220.254"),
        new Unit(45, "Ban CHQS xã Đạ Huoai 3", "86.250.5.128/27", "255.255.255.224", "86.250.5.129", "86.250.220.89", "86.250.220.254"),
        new Unit(46, "Ban CHQS xã Đạ Tẻh", "86.250.5.160/27", "255.255.255.224", "86.250.5.161", "86.250.220.91", "86.250.220.254"),
        new Unit(47, "Ban CHQS xã Đạ Tẻh 2", "86.250.5.192/27", "255.255.255.224", "86.250.5.193", "86.250.220.93", "86.250.220.254"),
        new Unit(48, "Ban CHQS xã Đạ Tẻh 3", "86.250.5.224/27", "255.255.255.224", "86.250.5.225", "86.250.220.95", "86.250.220.254"),
        new Unit(49, "Ban CHQS xã Cát Tiên", "86.250.6.0/27", "255.255.255.224", "86.250.6.1", "86.250.220.97", "86.250.220.254"),
        new Unit(50, "Ban CHQS xã Cát Tiên 2", "86.250.6.32/27", "255.255.255.224", "86.250.6.33", "86.250.220.99", "86.250.220.254"),
        new Unit(51, "Ban CHQS xã Cát Tiên 3", "86.250.6.64/27", "255.255.255.224", "86.250.6.65", "86.250.220.101", "86.250.220.254"),
        new Unit(52, "Ban CHQS xã Kiến Đức", "86.250.6.96/27", "255.255.255.224", "86.250.6.97", "86.250.220.103", "86.250.220.254"),
        new Unit(53, "Ban CHQS xã Nhân Cơ", "86.250.6.128/27", "255.255.255.224", "86.250.6.129", "86.250.220.105", "86.250.220.254"),
        new Unit(54, "Ban CHQS xã Quảng Tín", "86.250.6.160/27", "255.255.255.224", "86.250.6.161", "86.250.220.107", "86.250.220.254"),
        new Unit(55, "Ban CHQS xã Tà Đùng", "86.250.6.192/27", "255.255.255.224", "86.250.6.193", "86.250.220.109", "86.250.220.254"),
        new Unit(56, "Ban CHQS xã Quảng Khê", "86.250.6.224/27", "255.255.255.224", "86.250.6.225", "86.250.220.111", "86.250.220.254"),
        new Unit(57, "Ban CHQS xã Quảng Hoà", "86.250.7.0/27", "255.255.255.224", "86.250.7.1", "86.250.220.113", "86.250.220.254"),
        new Unit(58, "Ban CHQS xã Đắk Wil", "86.250.7.32/27", "255.255.255.224", "86.250.7.33", "86.250.220.115", "86.250.220.254"),
        new Unit(59, "Ban CHQS xã Nam Dong", "86.250.7.64/27", "255.255.255.224", "86.250.7.65", "86.250.220.117", "86.250.220.254"),
        new Unit(60, "Ban CHQS xã Cơ Jut", "86.250.7.96/27", "255.255.255.224", "86.250.7.97", "86.250.220.119", "86.250.220.254"),
        new Unit(61, "Ban CHQS xã Thuận An", "86.250.7.128/27", "255.255.255.224", "86.250.7.129", "86.250.220.121", "86.250.220.254"),
        new Unit(62, "Ban CHQS xã Đức Lập", "86.250.7.160/27", "255.255.255.224", "86.250.7.161", "86.250.220.123", "86.250.220.254"),
        new Unit(63, "Ban CHQS xã Đắk Mil", "86.250.7.192/27", "255.255.255.224", "86.250.7.193", "86.250.220.125", "86.250.220.254"),
        new Unit(64, "Ban CHQS xã Đắk Săk", "86.250.7.224/27", "255.255.255.224", "86.250.7.225", "86.250.220.127", "86.250.220.254"),
        new Unit(65, "Ban CHQS xã Nam Đà", "86.250.8.0/27", "255.255.255.224", "86.250.8.1", "86.250.220.129", "86.250.220.254"),
        new Unit(66, "Ban CHQS xã Krông Nô", "86.250.8.32/27", "255.255.255.224", "86.250.8.33", "86.250.220.131", "86.250.220.254"),
        new Unit(67, "Ban CHQS xã Nậm Nung", "86.250.8.64/27", "255.255.255.224", "86.250.8.65", "86.250.220.133", "86.250.220.254"),
        new Unit(68, "Ban CHQS xã Quảng Phú", "86.250.8.96/27", "255.255.255.224", "86.250.8.97", "86.250.220.135", "86.250.220.254"),
        new Unit(69, "Ban CHQS xã Đăk Song", "86.250.8.128/27", "255.255.255.224", "86.250.8.129", "86.250.220.137", "86.250.220.254"),
        new Unit(70, "Ban CHQS xã Đức An", "86.250.8.160/27", "255.255.255.224", "86.250.8.161", "86.250.220.139", "86.250.220.254"),
        new Unit(71, "Ban CHQS xã Thuận Hạnh", "86.250.8.192/27", "255.255.255.224", "86.250.8.193", "86.250.220.141", "86.250.220.254"),
        new Unit(72, "Ban CHQS xã Trường Xuân", "86.250.8.224/27", "255.255.255.224", "86.250.8.225", "86.250.220.143", "86.250.220.254"),
        new Unit(73, "Ban CHQS xã Quảng Sơn", "86.250.9.0/27", "255.255.255.224", "86.250.9.1", "86.250.220.145", "86.250.220.254"),
        new Unit(74, "Ban CHQS Phường Bắc Gia Nghĩa", "86.250.9.32/27", "255.255.255.224", "86.250.9.33", "86.250.220.147", "86.250.220.254"),
        new Unit(75, "Ban CHQS Phường Đông Gia Nghĩa", "86.250.9.64/27", "255.255.255.224", "86.250.9.65", "86.250.220.149", "86.250.220.254"),
        new Unit(76, "Ban CHQS Phường Nam Gia Nghĩa", "86.250.9.96/27", "255.255.255.224", "86.250.9.97", "86.250.220.151", "86.250.220.254"),
        new Unit(77, "Ban CHQS xã Quảng Trực", "86.250.9.128/27", "255.255.255.224", "86.250.9.129", "86.250.220.153", "86.250.220.254"),
        new Unit(78, "Ban CHQS xã Quảng Tân", "86.250.9.160/27", "255.255.255.224", "86.250.9.161", "86.250.220.155", "86.250.220.254"),
        new Unit(79, "Ban CHQS xã Tuy Đức", "86.250.9.192/27", "255.255.255.224", "86.250.9.193", "86.250.220.157", "86.250.220.254"),
        new Unit(80, "Ban CHQS xã Hàm Thạnh", "86.250.9.224/27", "255.255.255.224", "86.250.9.225", "86.250.220.159", "86.250.220.254"),
        new Unit(81, "Ban CHQS xã Hàm Kiệm", "86.250.10.0/27", "255.255.255.224", "86.250.10.1", "86.250.220.161", "86.250.220.254"),
        new Unit(82, "Ban CHQS xã Tân Thành", "86.250.10.32/27", "255.255.255.224", "86.250.10.33", "86.250.220.163", "86.250.220.254"),
        new Unit(83, "Ban CHQS xã Hàm Thuận Nam", "86.250.10.64/27", "255.255.255.224", "86.250.10.65", "86.250.220.165", "86.250.220.254"),
        new Unit(84, "Ban CHQS xã Tân Lập", "86.250.10.96/27", "255.255.255.224", "86.250.10.97", "86.250.220.167", "86.250.220.254"),
        new Unit(85, "Ban CHQS xã Tân Minh", "86.250.10.128/27", "255.255.255.224", "86.250.10.129", "86.250.220.169", "86.250.220.254"),
        new Unit(86, "Ban CHQS xã Hàm Tân", "86.250.10.160/27", "255.255.255.224", "86.250.10.161", "86.250.220.171", "86.250.220.254"),
        new Unit(87, "Ban CHQS xã Sơn Mỹ", "86.250.10.192/27", "255.255.255.224", "86.250.10.193", "86.250.220.173", "86.250.220.254"),
        new Unit(88, "Ban CHQS Phường La Gi", "86.134.156.0/24", "255.255.255.0", "86.134.156.254", "86.134.240.5", "86.134.240.1"),
        new Unit(89, "Ban CHQS Phường Phước Hội", "86.250.11.0/27", "255.255.255.224", "86.250.11.1", "86.250.220.177", "86.250.220.254"),
        new Unit(90, "Ban CHQS xã Tân Hải", "86.250.11.32/27", "255.255.255.224", "86.250.11.33", "86.250.220.179", "86.250.220.254"),
        new Unit(91, "Ban CHQS xã Nghị Đức", "86.250.11.64/27", "255.255.255.224", "86.250.11.65", "86.250.220.181", "86.250.220.254"),
        new Unit(92, "Ban CHQS xã Bắc Ruộng", "86.250.11.96/27", "255.255.255.224", "86.250.11.97", "86.250.220.183", "86.250.220.254"),
        new Unit(93, "Ban CHQS xã Đồng Kho", "86.250.11.128/27", "255.255.255.224", "86.250.11.129", "86.250.220.185", "86.250.220.254"),
        new Unit(94, "Ban CHQS xã Tánh Linh", "86.250.11.160/27", "255.255.255.224", "86.250.11.161", "86.250.220.187", "86.250.220.254"),
        new Unit(95, "Ban CHQS xã Suối Kiết", "86.250.11.192/27", "255.255.255.224", "86.250.11.193", "86.250.220.189", "86.250.220.254"),
        new Unit(96, "Ban CHQS xã Nam Thành", "86.250.11.224/27", "255.255.255.224", "86.250.11.225", "86.250.220.191", "86.250.220.254"),
        new Unit(97, "Ban CHQS xã Đức Linh", "86.250.12.0/27", "255.255.255.224", "86.250.12.1", "86.250.220.193", "86.250.220.254"),
        new Unit(98, "Ban CHQS xã Hoài Đức", "86.250.12.32/27", "255.255.255.224", "86.250.12.33", "86.250.220.195", "86.250.220.254"),
        new Unit(99, "Ban CHQS xã Trà Tân", "86.250.12.64/27", "255.255.255.224", "86.250.12.65", "86.250.220.197", "86.250.220.254"),
        new Unit(100, "Ban CHQS xã Vĩnh Hảo", "86.250.12.96/27", "255.255.255.224", "86.250.12.97", "86.250.220.199", "86.250.220.254"),
        new Unit(101, "Ban CHQS xã Liên Hương", "86.250.12.128/27", "255.255.255.224", "86.250.12.129", "86.250.220.201", "86.250.220.254"),
        new Unit(102, "Ban CHQS xã Tuy Phong", "86.250.12.160/27", "255.255.255.224", "86.250.12.161", "86.250.220.203", "86.250.220.254"),
        new Unit(103, "Ban CHQS xã Phan Rí Cửa", "86.250.12.192/27", "255.255.255.224", "86.250.12.193", "86.250.220.205", "86.250.220.254"),
        new Unit(104, "Ban CHQS xã Bắc Bình", "86.250.12.224/27", "255.255.255.224", "86.250.12.225", "86.250.220.207", "86.250.220.254"),
        new Unit(105, "Ban CHQS xã Hồng Thái", "86.250.13.0/27", "255.255.255.224", "86.250.13.1", "86.250.220.209", "86.250.220.254"),
        new Unit(106, "Ban CHQS xã Hải Ninh", "86.250.13.32/27", "255.255.255.224", "86.250.13.33", "86.250.220.211", "86.250.220.254"),
        new Unit(107, "Ban CHQS xã Phan Sơn", "86.250.13.64/27", "255.255.255.224", "86.250.13.65", "86.250.220.213", "86.250.220.254"),
        new Unit(108, "Ban CHQS xã Sông Luỹ", "86.250.13.96/27", "255.255.255.224", "86.250.13.97", "86.250.220.215", "86.250.220.254"),
        new Unit(109, "Ban CHQS xã Lương Sơn", "86.250.13.128/27", "255.255.255.224", "86.250.13.129", "86.250.220.217", "86.250.220.254"),
        new Unit(110, "Ban CHQS xã Hoà Thắng", "86.250.13.160/27", "255.255.255.224", "86.250.13.161", "86.250.220.219", "86.250.220.254"),
        new Unit(111, "Ban CHQS xã Đông Giang", "86.250.13.192/27", "255.255.255.224", "86.250.13.193", "86.250.220.221", "86.250.220.254"),
        new Unit(112, "Ban CHQS xã La Dạ", "86.250.13.224/27", "255.255.255.224", "86.250.13.225", "86.250.220.223", "86.250.220.254"),
        new Unit(113, "Ban CHQS xã Hàm Thuận Bắc", "86.250.14.0/27", "255.255.255.224", "86.250.14.1", "86.250.220.225", "86.250.220.254"),
        new Unit(114, "Ban CHQS xã Hàm Thuận", "86.250.14.32/27", "255.255.255.224", "86.250.14.33", "86.250.220.227", "86.250.220.254"),
        new Unit(115, "Ban CHQS xã Hồng Sơn", "86.250.14.64/27", "255.255.255.224", "86.250.14.65", "86.250.220.229", "86.250.220.254"),
        new Unit(116, "Ban CHQS xã Hàm Liêm", "86.250.14.96/27", "255.255.255.224", "86.250.14.97", "86.250.220.231", "86.250.220.254"),
        new Unit(117, "Ban CHQS Phường Hàm Thắng", "86.250.14.128/27", "255.255.255.224", "86.250.14.129", "86.250.220.233", "86.250.220.254"),
        new Unit(118, "Ban CHQS Phường Bình Thuận", "86.250.14.160/27", "255.255.255.224", "86.250.14.161", "86.250.220.235", "86.250.220.254"),
        new Unit(119, "Ban CHQS Phường Mũi Né", "86.250.14.192/27", "255.255.255.224", "86.250.14.193", "86.250.220.237", "86.250.220.254"),
        new Unit(120, "Ban CHQS Phường Phú Thuỷ", "86.250.14.224/27", "255.255.255.224", "86.250.14.225", "86.250.220.239", "86.250.220.254"),
        new Unit(121, "Ban CHQS Phường Phan Thiết", "86.250.15.0/27", "255.255.255.224", "86.250.15.1", "86.250.220.241", "86.250.220.254"),
        new Unit(122, "Ban CHQS Phường Tiến Thành", "86.250.15.32/27", "255.255.255.224", "86.250.15.33", "86.250.220.243", "86.250.220.254"),
        new Unit(123, "Ban CHQS xã Tuyên Quang", "86.250.15.64/27", "255.255.255.224", "86.250.15.65", "86.250.220.245", "86.250.220.254"),
        new Unit(124, "Ban CHQS Đặc Khu Phú Quý", "86.250.15.96/27", "255.255.255.224", "86.250.15.97", "86.250.220.247", "86.250.220.254"),
        new Unit(126, "Trung đoàn 40", "86.68.236.0/24", "255.255.255.0", "86.68.236.254", "86.68.252.151", "86.68.252.145"),
        new Unit(127, "Trung đoàn 812", "86.146.112.0/24", "255.255.255.0", "86.146.112.254", "86.146.240.12", "86.146.240.9"),
        new Unit(128, "Trung đoàn 812 (CS2)", "86.128.136.0/24", "255.255.255.0", "86.128.136.254", "86.128.255.138", "86.128.255.137"),
        new Unit(129, "Trung đoàn 994A", "86.154.136.0/24", "255.255.255.0", "86.154.136.254", "86.64.240.73", "86.64.240.65"),
        new Unit(130, "Trung đoàn 994B", "86.152.200.0/24", "255.255.255.0", "86.152.200.254", "86.146.240.57", "86.146.240.49"),
        new Unit(131, "Bộ CHQS tỉnh Lâm Đồng", "86.134.32.0/24", "255.255.255.0", "86.134.32.254", "86.180.254.5", "86.180.254.1"),
    };

    /// <summary>DNS co dinh cua toan bo he thong mang quan su.</summary>
    public const string MilitaryDns = "86.0.188.1";

    /// <summary>
    /// Tim don vi chua dia chi IP may tinh dang dung.
    ///
    /// Khop theo phep tinh network chuan: (ip AND mask) == (network AND mask).
    /// Cach nay dung cho moi dai (tu /24 den /27) va KHONG nham sang don vi
    /// lien ke (vi du 86.250.15.100 thuoc 86.250.15.96/27, khong phai 86.250.15.0/27).
    /// </summary>
    public static Unit? FindByLanIp(string ip)
    {
        if (!IPAddress.TryParse(ip?.Trim(), out var addr)) return null;
        if (addr.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) return null;

        foreach (var u in All)
        {
            if (IsIpInUnit(ip, u)) return u;
        }
        return null;
    }

    /// <summary>Tim don vi theo dia chi default gateway hien tai cua may.</summary>
    /// <remarks>
    /// CHI khop voi Gateway LAN - vi moi don vi co mot gateway LAN rieng.
    /// KHONG khop voi Gateway WAN: 86.250.220.254 la gateway WAN dung chung cho
    /// 122 don vi, khop vao se bao sai don vi (thuong la don vi dau tien).
    ///
    /// LUU Y: neu hai don vi cung mot gateway LAN thi gateway KHONG du de
    /// xac dinh don vi - dung FindByGatewayCandidates de biet tat ca phuong an.
    /// </remarks>
    public static Unit? FindByGateway(string gateway)
    {
        var list = FindByGatewayCandidates(gateway);
        return list.Count == 1 ? list[0] : null;
    }

    /// <summary>
    /// Tra ve DANH SACH don vi co gateway LAN giong voi dia chi cho.
    /// Neu chi co 1 don vi -> xac dinh duy nhat.
    /// Neu nhieu don vi -> khong the phan biet chi tu gateway (tra null).
    /// </summary>
    public static List<Unit> FindByGatewayCandidates(string gateway)
    {
        if (string.IsNullOrWhiteSpace(gateway)) return new List<Unit>();
        string gw = gateway.Trim();

        return All.Where(u =>
            string.Equals(u.LanGateway, gw, StringComparison.OrdinalIgnoreCase)).ToList();
    }

    /// <summary>Tim don vi theo dia chi IP wan cua modem.</summary>
    public static Unit? FindByWanIp(string wanIp)
    {
        if (string.IsNullOrWhiteSpace(wanIp)) return null;
        return All.FirstOrDefault(u =>
            string.Equals(u.WanIp, wanIp.Trim(), StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Gateway WAN co dung chung cho nhieu don vi hay khong.
    /// Tra ve danh sach don vi dung chung gateway do.
    /// </summary>
    public static List<Unit> FindBySharedWanGateway(string gateway)
    {
        if (string.IsNullOrWhiteSpace(gateway)) return new List<Unit>();
        string gw = gateway.Trim();

        return All.Where(u =>
            string.Equals(u.WanGateway, gw, StringComparison.OrdinalIgnoreCase)).ToList();
    }

    /// <summary>
    /// Tra ve danh sach don vi theo ten - dung cho combobox chon don vi.
    /// </summary>
    public static List<Unit> SortedByName() =>
        All.OrderBy(u => u.Name, StringComparer.CurrentCultureIgnoreCase).ToList();

    /// <summary>
    /// Kiem tra dia chi IP co nam trong dai LAN cua don vi hay khong.
    /// Dung phep tinh network chuan tren ca IP va network cua don vi.
    /// </summary>
    public static bool IsIpInUnit(string ip, Unit unit)
    {
        if (!IPAddress.TryParse(ip?.Trim(), out var addr)) return false;
        if (!TryGetNetwork(unit.LanCidr, out var net)) return false;

        var a = addr.GetAddressBytes();
        var n = net.GetAddressBytes();
        var m = ParseMask(unit.SubnetMask);

        for (int i = 0; i < 4; i++)
            if ((a[i] & m[i]) != (n[i] & m[i])) return false;

        return true;
    }

    /// <summary>
    /// Tach chuoi CIDR (vd "86.250.0.32/27") ra dia chi network.
    /// </summary>
    public static bool TryGetNetwork(string cidr, out IPAddress network)
    {
        network = IPAddress.None;
        if (string.IsNullOrWhiteSpace(cidr)) return false;

        string[] parts = cidr.Split('/');
        if (!IPAddress.TryParse(parts[0].Trim(), out var net)) return false;

        if (parts.Length > 1 && int.TryParse(parts[1].Trim(), out int prefix))
        {
            var mask = new byte[4];
            int bits = Math.Clamp(prefix, 0, 32);
            for (int i = 0; i < 4; i++)
            {
                int bitsInByte = Math.Clamp(bits - i * 8, 0, 8);
                mask[i] = (byte)(bitsInByte == 0 ? 0 : 0xFF << (8 - bitsInByte));
            }

            var n = net.GetAddressBytes();
            for (int i = 0; i < 4; i++) n[i] = (byte)(n[i] & mask[i]);
            network = new IPAddress(n);
            return true;
        }

        network = net;
        return true;
    }

    /// <summary>Chuyen subnet mask dang chuoi thanh 4 byte.</summary>
    private static byte[] ParseMask(string mask)
    {
        var result = new byte[] { 255, 255, 255, 255 };
        if (!IPAddress.TryParse(mask?.Trim(), out var m)) return result;

        var b = m.GetAddressBytes();
        if (b.Length == 4) b.CopyTo(result, 0);
        return result;
    }

    /// <summary>
    /// Tinh so host trong mot dai (vd /27 -> 32 dia chi, /24 -> 256 dia chi).
    /// </summary>
    public static int GetHostBlock(string cidr)
    {
        if (!TryGetNetwork(cidr, out var net)) return 256;

        var b = net.GetAddressBytes();
        uint value = ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];

        int prefix = 0;
        for (int i = 31; i >= 0; i--)
        {
            if (((value >> i) & 1) == 1) { prefix = i + 1; break; }
        }
        return 1 << (32 - prefix);
    }
}
