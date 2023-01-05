import http from 'k6/http';
import { sleep } from 'k6';

export const options = {
    duration: '1m',
    vus: 50,
    thresholds: {
        http_req_failed: ['rate<0.01'], // http errors should be less than 1%
        http_req_duration: ['p(95)<500'], // 95 percent of response times must be below 500ms
    },
};

export default function () {
    const res = http.get('https://test.k6.io');
    sleep(1);
}
export function handleSummary(data) {
    console.log('Finished executing performance tests');

    return {
        'stdout': textSummary(data, { indent: ' ', enableColors: true }), // Show the text summary to stdout...
        'summary.json': JSON.stringify(data), // and a JSON with all the details...
    };
}