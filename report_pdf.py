"""
PDF Report Generator – Safe Scanner Ultimate
ينشئ تقرير PDF احترافي من نتائج الفحص.
يستخدم مكتبة fpdf2 (تثبيت: pip install fpdf2).
"""
from fpdf import FPDF
from datetime import datetime
import os

class PDFReport(FPDF):
    def __init__(self, scan_name="تقرير Safe Scanner"):
        super().__init__(orientation='L', unit='mm', format='A4')
        self.scan_name = scan_name
        self.add_font('DejaVu', '', r'C:\Windows\Fonts\DejaVuSans.ttf', uni=True)
        self.add_font('DejaVu', 'B', r'C:\Windows\Fonts\DejaVuSans-Bold.ttf', uni=True)
        self.add_page()

    def header(self):
        self.set_font('DejaVu', 'B', 14)
        self.cell(0, 10, self.scan_name, align='C')
        self.ln(15)

    def footer(self):
        self.set_y(-15)
        self.set_font('DejaVu', '', 8)
        self.cell(0, 10, f'تم توليده في {datetime.now().strftime("%Y-%m-%d %H:%M")} | Safe Scanner Ultimate | بواسطة sh3la & Rlue', align='C')

    def add_results_table(self, results):
        self.set_font('DejaVu', 'B', 9)
        col_widths = [25, 20, 35, 55, 100, 55]
        headers = ['الخطورة', 'النسبة', 'التصنيف', 'الاسم', 'المسار', 'الأسباب']
        for i, header in enumerate(headers):
            self.cell(col_widths[i], 8, header, border=1, align='C')
        self.ln()

        self.set_font('DejaVu', '', 8)
        for r in results:
            sev = r.get('severity', 'Low')
            if sev == 'High':
                self.set_fill_color(255, 200, 200)
            elif sev == 'Medium':
                self.set_fill_color(255, 243, 205)
            else:
                self.set_fill_color(212, 237, 218)
            self.cell(col_widths[0], 7, sev, border=1, fill=True, align='C')
            self.cell(col_widths[1], 7, f"{r.get('score','0')}%", border=1, fill=True, align='C')
            self.cell(col_widths[2], 7, r.get('category','')[:20], border=1, fill=True)
            self.cell(col_widths[3], 7, r.get('name','')[:30], border=1, fill=True)
            self.cell(col_widths[4], 7, r.get('path','')[:55], border=1, fill=True)
            reasons = ' | '.join(r.get('reasons', []))[:55]
            self.cell(col_widths[5], 7, reasons, border=1, fill=True)
            self.ln()

    def add_summary(self, results):
        total = len(results)
        high = sum(1 for r in results if r.get('severity') == 'High')
        med = sum(1 for r in results if r.get('severity') == 'Medium')
        low = sum(1 for r in results if r.get('severity') == 'Low')
        self.ln(5)
        self.set_font('DejaVu', 'B', 10)
        self.cell(0, 8, f'إجمالي النتائج: {total} | 🔴 عالي: {high} | 🟡 متوسط: {med} | 🟢 منخفض: {low}', align='C')
        self.ln(10)


def generate_pdf_report(results, file_path, scan_name="تقرير Safe Scanner"):
    """توليد ملف PDF من النتائج وحفظه في file_path."""
    pdf = PDFReport(scan_name)
    pdf.add_results_table(results)
    pdf.add_summary(results)
    pdf.output(file_path)
    return file_path