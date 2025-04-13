import io
from PyPDF2 import PdfWriter, PdfReader
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter

def create_pdf():
    # Create a memory buffer for the PDF
    packet = io.BytesIO()
    
    # Create a new PDF with Reportlab
    can = canvas.Canvas(packet, pagesize=letter)
    y = 750  # Start from top of page
    
    # Read and write the text
    with open('sample_threat_report.txt', 'r') as file:
        for line in file:
            if y < 50:  # If near bottom of page
                can.showPage()
                y = 750
            can.drawString(50, y, line.strip())
            y -= 15
    
    can.save()
    
    # Move to the beginning of the buffer
    packet.seek(0)
    
    # Create a new PDF with PyPDF2
    new_pdf = PdfReader(packet)
    
    # Write the new PDF to a file
    output = PdfWriter()
    for page in new_pdf.pages:
        output.add_page(page)
    
    # Finally, write the PDF to a file
    with open("sample_threat_report.pdf", "wb") as output_file:
        output.write(output_file)

if __name__ == "__main__":
    create_pdf() 