"""Document Management and Ingestion API Routes.

Handles PDF uploads, safe remote document ingestion, and provenance querying.
"""

from typing import List

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Request,
    Response,
    UploadFile,
    status,
)
from pydantic import BaseModel

from backend.app.dependencies import get_current_user_context
from backend.app.ingestion.ingestion_pipeline import ingestion_pipeline
from backend.app.ingestion.provenance import DocumentProvenance, provenance_registry
from backend.app.retrieval.embeddings import embedding_provider
from backend.app.retrieval.vector_store import vector_store
from backend.app.security.access_control import DocumentClassification, UserContext

router = APIRouter(prefix="/documents", tags=["Documents"])


class RemoteDocumentRequest(BaseModel):
    url: str
    doc_title: str
    publisher: str
    classification: DocumentClassification = DocumentClassification.PUBLIC
    allowed_roles: List[str] = ["viewer", "engineer", "admin"]


@router.post("/upload", status_code=status.HTTP_201_CREATED)
async def upload_document(
    request: Request,
    response: Response,
    file: UploadFile = File(...),
    doc_title: str = Form(...),
    publisher: str = Form(...),
    classification: str = Form("PUBLIC"),
    user: UserContext = Depends(get_current_user_context),
):
    """Upload and ingest a local PDF document with full validation and chunk indexing."""
    content = await file.read()
    client_ip = request.client.host if request.client else "127.0.0.1"

    try:
        doc_class = DocumentClassification(classification.upper())
    except ValueError:
        doc_class = DocumentClassification.PUBLIC

    res = ingestion_pipeline.ingest_pdf_bytes(
        content=content,
        filename=file.filename or "document.pdf",
        doc_title=doc_title,
        publisher=publisher,
        classification=doc_class,
        client_ip=client_ip,
    )

    if res["status"] == "FAILED":
        raise HTTPException(status_code=400, detail=res["error"])

    if res["status"] == "DUPLICATE":
        response.status_code = status.HTTP_200_OK
        return {
            "status": "DUPLICATE",
            "message": res["message"],
            "doc_id": res["doc_id"],
            "sha256_hash": res["sha256_hash"],
        }

    # Index chunks into vector store
    chunks = res.pop("chunks", [])
    if chunks:
        texts = [c.text for c in chunks]
        embeddings = embedding_provider.embed_batch(texts)
        vector_store.add_chunks(chunks, embeddings)

    return res


@router.post("/remote", status_code=status.HTTP_201_CREATED)
def ingest_remote_document(
    request: Request,
    payload: RemoteDocumentRequest,
    user: UserContext = Depends(get_current_user_context),
):
    """Ingest a PDF from an approved HTTPS URL with strict SSRF protections."""
    client_ip = request.client.host if request.client else "127.0.0.1"

    try:
        content = ingestion_pipeline.fetch_remote_pdf(
            url=payload.url, client_ip=client_ip
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

    filename = payload.url.split("/")[-1] or "remote_doc.pdf"
    if not filename.endswith(".pdf"):
        filename += ".pdf"

    res = ingestion_pipeline.ingest_pdf_bytes(
        content=content,
        filename=filename,
        doc_title=payload.doc_title,
        publisher=payload.publisher,
        source_url=payload.url,
        classification=payload.classification,
        allowed_roles=payload.allowed_roles,
        client_ip=client_ip,
    )

    if res["status"] == "FAILED":
        raise HTTPException(status_code=400, detail=res["error"])

    # Index chunks into vector store
    chunks = res.pop("chunks", [])
    if chunks:
        texts = [c.text for c in chunks]
        embeddings = embedding_provider.embed_batch(texts)
        vector_store.add_chunks(chunks, embeddings)

    return res


@router.get("", response_model=List[DocumentProvenance])
def list_documents(user: UserContext = Depends(get_current_user_context)):
    """List all registered document provenance records."""
    return provenance_registry.list_all()


@router.get("/{doc_id}", response_model=DocumentProvenance)
def get_document(doc_id: str, user: UserContext = Depends(get_current_user_context)):
    """Retrieve provenance and integrity record for a specific document."""
    doc = provenance_registry.get_by_id(doc_id)
    if not doc:
        raise HTTPException(status_code=404, detail=f"Document '{doc_id}' not found")
    return doc
