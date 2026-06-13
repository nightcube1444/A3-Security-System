from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    PageBreak
)

from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from datetime import datetime
from pathlib import Path


class A3PDFGenerator:

    def __init__(self):
        self.styles = getSampleStyleSheet()

    def generate_report(
        self,
        report_title,
        findings,
        output_file
    ):

        doc = SimpleDocTemplate(output_file)

        story = []

        title = Paragraph(
            report_title,
            self.styles["Title"]
        )

        story.append(title)
        story.append(Spacer(1, 12))

        story.append(
            Paragraph(
                f"Generated: {datetime.now()}",
                self.styles["Normal"]
            )
        )

        story.append(Spacer(1, 20))

        for finding in findings:

            severity = finding.get(
                "severity",
                "UNKNOWN"
            )

            color = colors.black

            if severity == "CRITICAL":
                color = colors.red

            elif severity == "HIGH":
                color = colors.orange

            elif severity == "MEDIUM":
                color = colors.darkgoldenrod

            heading = Paragraph(
                f"<font color='{color.hexval()}'>"
                f"{finding['title']}"
                f"</font>",
                self.styles["Heading2"]
            )

            story.append(heading)

            story.append(
                Paragraph(
                    f"Severity: {severity}",
                    self.styles["Normal"]
                )
            )

            story.append(
                Paragraph(
                    f"Score: {finding.get('score', 0)}",
                    self.styles["Normal"]
                )
            )

            story.append(
                Paragraph(
                    finding.get(
                        "description",
                        "No description"
                    ),
                    self.styles["BodyText"]
                )
            )

            story.append(Spacer(1, 12))

        story.append(PageBreak())

        story.append(
            Paragraph(
                "A3 Security System Report",
                self.styles["Heading1"]
            )
        )

        doc.build(story)

        return output_file


if __name__ == "__main__":

    findings = [

        {
            "title": "Malicious Sandbox Sample",
            "severity": "CRITICAL",
            "score": 110,
            "description":
                "Detected subprocess execution "
                "and base64 payload."
        },

        {
            "title": "Suspicious Socket Usage",
            "severity": "MEDIUM",
            "score": 50,
            "description":
                "Network communication detected."
        }
    ]

    output = (
        Path(__file__).parent.parent
        / "reports"
        / "a3_report.pdf"
    )

    output.parent.mkdir(
        exist_ok=True
    )

    pdf = A3PDFGenerator()

    pdf.generate_report(
        "A3 Threat Report",
        findings,
        str(output)
    )

    print(
        f"Report generated: {output}"
    )