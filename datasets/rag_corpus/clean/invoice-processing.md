# Invoice Processing

The accounts payable team at Acme Corp processes supplier invoices. Invoices arrive in the accounts payable mailbox and are loaded into BuyRight automatically, where each invoice is matched to its purchase order.

Acme uses a three-way match: the purchase order, the goods receipt and the invoice must agree on quantity and price within a 2% tolerance. Invoices that do not match are routed to the budget owner for review, and the vendor is contacted if a corrected invoice is needed.

Standard payment terms are net 30, meaning invoices are due 30 days after the invoice date. Vendors offering an early payment discount of 2% for payment within 10 days are paid early whenever cash planning allows.

Payment runs take place every Tuesday and Friday. Payments go out by ACH in the United States and by SEPA transfer in Europe; paper checks are issued only on request. Invoices for services without a purchase order are held until a purchase order is raised.

Duplicate invoices are detected by BuyRight using the vendor number, invoice number and amount. Vendors check payment status in the BuyRight supplier portal. Accounts payable closes the books for each month on the third business day of the following month.
