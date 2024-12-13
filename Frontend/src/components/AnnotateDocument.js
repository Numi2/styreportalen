import React, { useState, useEffect } from 'react';
import { Document, Page, pdfjs } from 'react-pdf';
import { PdfLoader, PdfHighlighter, Tip, Highlight, Popup } from "react-pdf-highlighter";
import axios from '../utils/axios';
import { useParams } from 'react-router-dom';
import { CircularProgress, Typography } from '@mui/material';

// Set workerSrc
pdfjs.GlobalWorkerOptions.workerSrc = `//cdnjs.cloudflare.com/ajax/libs/pdf.js/${pdfjs.version}/pdf.worker.js`;

const AnnotateDocument = () => {
  const { id } = useParams(); // Document ID
  const [pdfUrl, setPdfUrl] = useState('');
  const [highlights, setHighlights] = useState([]);

  useEffect(() => {
    // Fetch the document's current file path
    const fetchDocument = async () => {
      try {
        const response = await axios.get(`/Documents/${id}`);
        setPdfUrl(`/api/Documents/${id}/Download`);
        setHighlights(response.data.highlights || []);
      } catch (error) {
        console.error(error);
      }
    };
    fetchDocument();
  }, [id]);

  const handleAddHighlight = async (highlight) => {
    setHighlights([...highlights, highlight]);
    // Save highlight to backend
    try {
      await axios.post(`/Highlights`, highlight);
    } catch (error) {
      console.error(error);
    }
  };

  return (
    <div>
      {pdfUrl ? (
        <PdfLoader url={pdfUrl}>
          {(pdfDocument) => (
            <PdfHighlighter
              pdfDocument={pdfDocument}
              enableAreaSelection={(event) => event.altKey}
              highlights={highlights}
              onScrollChange={() => {}}
              onSelectionFinished={(position, content, hideTipAndSelection, transformSelection) => (
                <Tip
                  onOpen={transformSelection}
                  onConfirm={(comment) => {
                    handleAddHighlight({ ...position, content, comment });
                    hideTipAndSelection();
                  }}
                />
              )}
              highlightTransform={(highlight, index, setTip, hideTip, viewportToScaled, screenshot) => {
                const isTextHighlight = !highlight.content && !highlight.image;

                const component = isTextHighlight ? (
                  <Highlight
                    key={index}
                    position={highlight}
                    comment={highlight.comment}
                  />
                ) : (
                  <Popup
                    key={index}
                    position={highlight.position}
                    onMouseOver={(popupContent) => setTip(popupContent)}
                    onMouseOut={hideTip}
                  >
                    {highlight.comment.text}
                  </Popup>
                );

                return component;
              }}
            />
          )}
        </PdfLoader>
      ) : (
        <CircularProgress />
      )}
    </div>
  );
};

export default AnnotateDocument;
