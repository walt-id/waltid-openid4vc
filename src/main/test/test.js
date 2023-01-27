import http from 'k6/http';
import { sleep } from 'k6';
import { textSummary } from 'https://jslib.k6.io/k6-summary/0.0.1/index.js';

export const options = {
    duration: '.5m',
    vus: 5,
    iterations: 10,
    thresholds: {
        http_req_failed: ['rate<0.01'], // http errors should be less than 1%
        http_req_duration: ['p(95)<500'], // 95 percent of response times must be below 500ms
    },
};



export default function () {
    let params = {
        "templateId": "VerifiableId",
        "config": {
            "issuerDid": "did:web:walt.id",
            "subjectDid": "did:web:walt.id"
        },
        "credentialData": {
            "credentialSubject": {
                "firstName": "issuance test"
            }
        }
    }
    const url = 'https://signatory.ssikit.walt.id/v1/swagger#/Credentials/issue';

    const res = (http.post(url, JSON.stringify(params),{  headers: { 'Content-Type': 'application/json' }}));
    sleep(1);
}
export function handleSummary(data) {
    console.log('Finished executing performance tests');

    return {
        'stdout': textSummary(data, { indent: ' ', enableColors: true }), // Show the text summary to stdout...
        'summary.json': JSON.stringify(data), // and a JSON with all the details...
    };
}
